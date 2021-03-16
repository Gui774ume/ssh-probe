/*
Copyright © 2020 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ssh_probe

import (
	"bytes"
	"strings"
	"time"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ssh-probe/pkg/assets"
	"github.com/Gui774ume/ssh-probe/pkg/model"
	"github.com/Gui774ume/ssh-probe/pkg/utils"
)

// SSHProbe is the main structure of the ssh probe project
type SSHProbe struct {
	profiles                 model.Profiles
	bootTime                 time.Time
	manager                  *manager.Manager
	accessControlEventsLevel model.Action
	disableGlobalScope       bool

	userProfileCookieMap *ebpf.Map
	allowedBinariesMap   *ebpf.Map
	mfaTokens            *ebpf.Map
	actions              *ebpf.Map
	inodes               *ebpf.Map

	inodeCache map[uint64]string

	agentURL      string
	logsForwarder *DatadogLogs
}

// Start ssh-probe
func (sshp *SSHProbe) Start() error {
	// setup the datadog logs forwarder
	if sshp.agentURL != "" {
		sshp.logsForwarder = &DatadogLogs{}
		if err := sshp.logsForwarder.Start(sshp.agentURL); err != nil {
			return errors.Wrap(err, "couldn't start the Datadog logs forwarder")
		}
	}

	// Load eBPF programs and maps
	if err := sshp.initManager(); err != nil {
		return err
	}

	// Select eBPF maps
	if err := sshp.initKernelMaps(); err != nil {
		return errors.Wrap(err, "failed to select kernel maps")
	}

	// Insert profiles in eBPF maps
	if err := sshp.insertProfiles(); err != nil {
		return errors.Wrap(err, "failed to insert user profiles in the kernel")
	}

	// Start the eBPF manager
	if err := sshp.manager.Start(); err != nil {
		return errors.Wrap(err, "failed to start eBPF manager")
	}
	return nil
}

// initManager retrieves the eBPF bytecode assets and insert them in the kernel
func (sshp *SSHProbe) initManager() error {
	buf, err := assets.Asset("/probe.o")
	if err != nil {
		return errors.Wrap(err, "failed to retrieve eBPF bytecode")
	}
	options := manager.Options{
		ConstantEditors: []manager.ConstantEditor{
			{
				Name:  "unknown_user_default",
				Value: uint64(sshp.profiles.UnknownUserDefault.KernelValue()),
			},
			{
				Name:  "access_control_events_level",
				Value: uint64(sshp.accessControlEventsLevel.KernelValue()),
			},
		},
	}

	// check which probes should be activated
	sshp.computeActivatedProbes(&options)

	if err := sshp.manager.InitWithOptions(bytes.NewReader(buf), options); err != nil {
		return errors.Wrap(err, "failed to init eBPF manager")
	}
	return nil
}

// computeActivatedProbes computes the list of probes that should be activated based on the available probes in the current kernel
func (sshp *SSHProbe) computeActivatedProbes(options *manager.Options) {
	for _, probe := range sshp.manager.Probes {
		// activate uprobes and tracepoints
		if strings.HasPrefix(probe.Section, "uprobe/") || strings.HasPrefix(probe.Section, "tracepoint/") {
			options.ActivatedProbes = append(options.ActivatedProbes, probe.Section)
			continue
		}

		// check symbols for kprobes / kretprobes
		if strings.HasPrefix(probe.Section, "kprobe/") || strings.HasPrefix(probe.Section, "kretprobe/") {
			sym := strings.TrimPrefix(probe.Section, "kprobe/")
			sym = strings.TrimPrefix(sym, "kretprobe/")
			foundSym, err := manager.FindFilterFunction(sym)
			if err == nil && foundSym == sym {
				options.ActivatedProbes = append(options.ActivatedProbes, probe.Section)
			} else {
				logrus.Debugf("couldn't find symbol: %s", probe.Section)
			}
		}
	}
}

// initKernelMaps prepares the kernel maps that ssh-probe will use to communicate with the eBPF programs
func (sshp *SSHProbe) initKernelMaps() error {
	var ok bool
	var err error

	// select user_profile_cookie map
	sshp.userProfileCookieMap, ok, err = sshp.manager.GetMap("user_profile_cookie")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("couldn't find user_profile_cookie map")
	}

	// select allowed_binaries map
	sshp.allowedBinariesMap, ok, err = sshp.manager.GetMap("allowed_binaries")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("couldn't find allowed_binaries map")
	}

	// select mfa_tokens map
	sshp.mfaTokens, ok, err = sshp.manager.GetMap("mfa_tokens")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("couldn't find mfa_tokens map")
	}

	// select actions map
	sshp.actions, ok, err = sshp.manager.GetMap("actions")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("couldn't find actions map")
	}

	// select inodes map
	sshp.inodes, ok, err = sshp.manager.GetMap("inodes")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("couldn't find inodes map")
	}
	return nil
}

// Forward forwards an event to Datadog
func (sshp *SSHProbe) Forward(event interface{}) {
	if sshp.logsForwarder != nil {
		sshp.logsForwarder.EventChan <- event
	}
}

// GetProfile returns a profile by its cookie
func (sshp *SSHProbe) GetProfile(cookie uint32) *model.Profile {
	for _, profile := range sshp.profiles.UserProfiles {
		if profile.KernelCookie == cookie {
			return profile
		}
	}
	return nil
}

// Stop ssh-probe
func (sshp *SSHProbe) Stop() error {
	// Stop the eBPF manager
	if err := sshp.manager.Stop(manager.CleanAll); err != nil {
		return err
	}
	return nil
}

// CacheInode caches the inode of the provided path
func (sshp *SSHProbe) CacheInode(path string) (uint64, error) {
	ino, err := utils.GetInode(path)
	if err != nil {
		return 0, err
	}
	sshp.inodeCache[ino] = path
	return ino, nil
}

// ResolveInode returns the path of the provided inode
func (sshp *SSHProbe) ResolveInode(ino uint64) (string, bool) {
	p, ok := sshp.inodeCache[ino]
	return p, ok
}

// LostHandler logs lost samples from perf ring buffers
func (sshp *SSHProbe) LostHandler(CPU int, count uint64, perfMap *manager.PerfMap, manager *manager.Manager) {
	logrus.Printf("lost %d samples from %s", count, perfMap.Name)
}
