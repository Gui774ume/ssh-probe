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
	"syscall"

	"github.com/DataDog/ebpf/manager"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/ssh-probe/pkg/model"
)

// HandleKillRequests handles process kill requests from the kernel
func (sshp *SSHProbe) HandleKillRequests(Cpu int, data []byte, perfMap *manager.PerfMap, m *manager.Manager) {
	request := &model.KillRequest{}
	if _, err := request.UnmarshalBinary(data, sshp.bootTime); err != nil {
		logrus.Warnf("error decoding KillRequest event: %v", err)
		return
	}

	// Select the corresponding user by its cookie
	profile := sshp.GetProfile(request.ProfileCookie)
	if profile == nil && request.ProfileCookie != model.UnknownUserNameCookie {
		logrus.Warnf("couldn't find profile for cookie %v", request.ProfileCookie)
	}
	if profile == nil {
		profile = &model.UnknownUserProfile
	}

	// kill the requested process
	if err := unix.Kill(int(request.SessionInitPid), syscall.SIGKILL); err != nil {
		if unix.ESRCH.Error() == err.Error() {
			// Session is already dead, ignore
			return
		}
		logrus.Errorf("couldn't kill session %v of user \"%s\" (login_timestamp: %v): %v", request.SessionCookie, profile.User, request.SessionLoginTimestamp, err)
	} else {
		logrus.Printf("session %v of user \"%s\" successfully killed (login_timestamp: %v)", request.SessionCookie, profile.User, request.SessionLoginTimestamp)
	}
}
