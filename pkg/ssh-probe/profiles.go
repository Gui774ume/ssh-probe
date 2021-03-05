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
	"fmt"
	"github.com/Gui774ume/ssh-probe/pkg/utils"
	"os"
	"strings"

	"github.com/dgryski/dgoogauth"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/Gui774ume/ssh-probe/pkg/model"
)

// insertProfiles calls insertProfile for user profile
func (sshp *SSHProbe) insertProfiles() error {
	for _, profile := range sshp.profiles.UserProfiles {
		if err := sshp.insertProfile(profile); err != nil {
			return err
		}
	}
	return nil
}

// insertProfile inserts the provided profile in the kernel
func (sshp *SSHProbe) insertProfile(profile *model.Profile) error {
	// generate random cookie
	profile.KernelCookie = utils.NewCookie()

	// insert allowed processes
	for path, action := range profile.Binaries {
		key, err := model.GetBinaryPathKey(profile.KernelCookie, path)
		if err != nil {
			return errors.Wrapf(err, "failed to generate binary path key for user \"%s\" and binary \"%s\"", profile.User, path)
		}
		if err := sshp.allowedBinariesMap.Put(key, action.KernelValue()); err != nil {
			return errors.Wrapf(err, "failed to insert process keys for user \"%s\" and binary \"%s\"", profile.User, path)
		}
	}

	// insert single actions
	if err := sshp.insertActions(profile); err != nil {
		return errors.Wrapf(err, "failed to insert actions for user \"%s\"", profile.User)
	}

	// insert FIM policies
	for _, f := range profile.FIM {
		for inode, path := range f.Inodes {
			sshp.inodeCache[inode] = path
			for _, ar := range f.AccessRight.KernelValues() {
				// prepare key
				key, err := model.GetInodeSelector(inode, profile.KernelCookie, ar)
				if err != nil {
					return errors.Wrapf(err, "failed to insert an inode for pattern %s", f.Pattern)
				}
				// insert
				if err := sshp.inodes.Put(key, f.Action.KernelValue()); err != nil {
					return errors.Wrapf(err, "failed to insert an inode <-> action for pattern %s", f.Pattern)
				}
			}
		}
	}

	// update username <-> profile cookie mapping
	usernameKey := profile.GetUserKey()
	if err := sshp.userProfileCookieMap.Put(usernameKey, profile.KernelCookie); err != nil {
		return errors.Wrapf(err, "failed to insert profile cookie for user \"%s\"", profile.User)
	}
	return nil
}

// insertActions inserts the single actions of the profile
func (sshp *SSHProbe) insertActions(profile *model.Profile) error {
	ak := model.ActionKey{
		ProfileCookie: profile.KernelCookie,
	}

	// Unknown binary
	ak.Category = model.CategoryUnknownBinary
	key, err := ak.GetActionKey()
	if err != nil {
		return err
	}
	if err := sshp.actions.Put(key, profile.UnknownBinaryDefault.KernelValue()); err != nil {
		return errors.Wrapf(err, "failed to insert unknown binary default action")
	}

	// Deletions and moves
	ak.Category = model.CategoryDeletionsAndMoves
	key, err = ak.GetActionKey()
	if err != nil {
		return err
	}
	if err := sshp.actions.Put(key, profile.DeletionsAndMoves.KernelValue()); err != nil {
		return errors.Wrapf(err, "failed to insert deletions and moves action")
	}

	// Socket creation
	ak.Category = model.CategorySocketCreation
	key, err = ak.GetActionKey()
	if err != nil {
		return err
	}
	if err := sshp.actions.Put(key, profile.SocketCreation.KernelValue()); err != nil {
		return errors.Wrapf(err, "failed to insert socket creation action")
	}

	// Privilege elevation
	ak.Category = model.CategoryPrivilegeElevation
	key, err = ak.GetActionKey()
	if err != nil {
		return err
	}
	if err := sshp.actions.Put(key, profile.PrivilegeElevation.KernelValue()); err != nil {
		return errors.Wrapf(err, "failed to insert privilege elevation action")
	}

	// OS level protections
	ak.Category = model.CategoryOSLevelProtections
	key, err = ak.GetActionKey()
	if err != nil {
		return err
	}
	if err := sshp.actions.Put(key, profile.OSLevelProtections.KernelValue()); err != nil {
		return errors.Wrapf(err, "failed to insert os level protections action")
	}

	// Process level protections
	ak.Category = model.CategoryProcessLevelProtections
	key, err = ak.GetActionKey()
	if err != nil {
		return err
	}
	if err := sshp.actions.Put(key, profile.ProcessLevelProtections.KernelValue()); err != nil {
		return errors.Wrapf(err, "failed to insert process level protections action")
	}

	// Performance monitoring
	ak.Category = model.CategoryPerformanceMonitoring
	key, err = ak.GetActionKey()
	if err != nil {
		return err
	}
	if err := sshp.actions.Put(key, profile.PerformanceMonitoring.KernelValue()); err != nil {
		return errors.Wrapf(err, "failed to insert performance monitoring action")
	}

	// kill
	ak.Category = model.CategoryKill
	key, err = ak.GetActionKey()
	if err != nil {
		return err
	}
	if err := sshp.actions.Put(key, profile.Kill.KernelValue()); err != nil {
		return errors.Wrapf(err, "failed to insert kill action")
	}
	return nil
}

// loadProfiles loads the profile at the provided path
func (sshp *SSHProbe) loadProfiles(profiles string) error {
	f, err := os.Open(profiles)
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()
	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&sshp.profiles); err != nil {
		return errors.WithStack(err)
	}

	// add the profiles file in each profile
	for _, profile := range sshp.profiles.UserProfiles {
		profile.FIM = append(profile.FIM, &model.FilePolicy{
			Pattern:     profiles,
			AccessRight: model.Any,
			Action:      model.Block,
		})
	}

	// Sanitize profiles values
	if err := sshp.profiles.Sanitize(); err != nil {
		return err
	}

	// Fetch secrets
	secretsEnv := os.Getenv("SSH_PROBE_SECRETS")
	if len(secretsEnv) == 0 {
		return errors.New("couldn't find any secret in SSH_PROBE_SECRETS environment variable")
	}
	secrets := strings.Split(secretsEnv, ",")
	for _, secret := range secrets {
		split := strings.Split(secret, ":")
		if len(split) != 2 {
			return fmt.Errorf("invalid SSH_PROBE_SECRETS format: %s", secret)
		}
		for _, profile := range sshp.profiles.UserProfiles {
			if split[0] == profile.User {
				profile.OTPConfig = &dgoogauth.OTPConfig{
					Secret:      split[1],
					WindowSize:  5,
					HotpCounter: 0,
				}
			}
		}
	}

	// Fetch inodes of each file pattern
	for _, profile := range sshp.profiles.UserProfiles {
		if err := sshp.loadProfileInodes(profile); err != nil {
			return errors.Wrapf(err, "failed to load profile inodes for user \"%s\"", profile.User)
		}
	}
	return nil
}

// loadProfileInodes loads the list of inodes that a profile will watch
func (sshp *SSHProbe) loadProfileInodes(profile *model.Profile) error {
	// Expand patterns
	for _, f := range profile.FIM {
		if err := f.ExpandPattern(); err != nil {
			return errors.Wrapf(err, "couldn't expand pattern %s", f.Pattern)
		}
	}
	return nil
}
