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
	"syscall"
	"time"

	"github.com/DataDog/ebpf/manager"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/Gui774ume/ssh-probe/pkg/model"
)

// HandleOTPRequests handles OTP requests from ssh-probe-auth
func (sshp *SSHProbe) HandleOTPRequests(Cpu int, data []byte, perfMap *manager.PerfMap, m *manager.Manager) {
	request := &model.OTPRequest{}
	if _, err := request.UnmarshalBinary(data, sshp.bootTime); err != nil {
		logrus.Warnf("error decoding OTPRequest: %v", err)
		sshp.sendAuthenticationResult(false, request, nil)
		return
	}

	// Check token validity
	if request.OTPTimeout > model.MaxOTPTimeout || request.OTPTimeout < 0 {
		err := fmt.Errorf("invalid OTP timeout requested (value must be between 0 and 10 minutes): %v", request.OTPTimeout)
		logrus.Warnf("invalid OTPRequest: %v", err)
		sshp.sendAuthenticationResult(false, request, nil)
		return
	}
	if request.OTPScope == model.CategoryGlobal && sshp.disableGlobalScope {
		logrus.Warnf("invalid OTPRequest: global MFA scope is disabled by config")
		sshp.sendAuthenticationResult(false, request, nil)
		return
	}

	// Select the right profile by its cookie
	profile := sshp.GetProfile(request.ProfileCookie)
	if profile == nil {
		logrus.Warnf("couldn't find profile for cookie %s", request.ProfileCookie)
		sshp.sendAuthenticationResult(false, request, profile)
		return
	}

	// Authenticate token
	if profile.OTPConfig == nil {
		logrus.Warnf("no OTPConfig available for \"%s\", did you provide a secret in SSH_PROBE_SECRETS for that user ?", profile.User)
		sshp.sendAuthenticationResult(false, request, profile)
		return
	}
	ok, err := profile.OTPConfig.Authenticate(request.OTPToken)
	if err != nil {
		logrus.Warnf("couldn't authenticate token \"%s\": %v", request.OTPToken, err)
		sshp.sendAuthenticationResult(false, request, profile)
		return
	}

	if ok {
		logrus.Printf("OTP authentication successful for user \"%s\" (session %v): token is valid for %v, scope is %s", profile.User, request.SessionCookie, request.OTPTimeout, request.OTPScope)
		if request.OTPScope == model.CategoryGlobal {
			for _, scope := range model.AllCategories {
				if err = sshp.insertMFAToken(profile.KernelCookie, request.SessionCookie, scope, request.OTPTimeout); err != nil {
					logrus.Errorf("failed to insert the OTP token in the kernel for user \"%s\" (session %v): %v", profile.User, request.SessionCookie, err)
				}
			}
		} else {
			if err = sshp.insertMFAToken(profile.KernelCookie, request.SessionCookie, request.OTPScope, request.OTPTimeout); err != nil {
				logrus.Errorf("failed to insert the OTP token in the kernel for user \"%s\" (session %v): %v", profile.User, request.SessionCookie, err)
			}
		}
	}
	sshp.sendAuthenticationResult(ok, request, profile)
}

func (sshp *SSHProbe) insertMFAToken(profileCookie uint32, sessionCookie uint32, scope model.Category, timeout time.Duration) error {
	// Insert access token
	selector := model.MFASelector{
		ProfileCookie: profileCookie,
		SessionCookie: sessionCookie,
		Scope:         scope,
	}
	key, err := selector.GetMFASelectorKey()
	if err != nil {
		return err
	}
	ts := time.Now().Add(timeout).Sub(sshp.bootTime).Nanoseconds()
	if err := sshp.mfaTokens.Put(key, &ts); err != nil {
		return err
	}
	return nil
}

func (sshp *SSHProbe) sendAuthenticationResult(success bool, request *model.OTPRequest, profile *model.Profile) {
	// Send authentication result to ssh-probe-auth
	if success {
		profile.OTPFailedRequests = 0
		// send SIGUSR1
		if err := unix.Kill(int(request.RequestPid), syscall.SIGUSR1); err != nil {
			logrus.Warnf("failed to sent OTP authentication result to ssh-probe-auth: %v", err)
		}

	} else {
		if profile != nil {
			// Check number of failed attempts
			profile.OTPFailedRequests++
			if profile.OTPFailedRequests >= model.MaxOTPFailures {
				logrus.Printf("OTP authentication failed %v times, killing session %v of user \"%s\" ...", profile.OTPFailedRequests, request.SessionCookie, profile.User)
				if err := unix.Kill(int(request.SessionInitPid), syscall.SIGKILL); err != nil {
					logrus.Errorf("couldn't kill session %v for user \"%s\" (login_timestamp: %v): %v", request.SessionCookie, profile.User, request.SessionLoginTimestamp, err)
				}

				// send a notification
				notification := &model.Notification{
					Timestamp:             request.Timestamp,
					SessionLoginTimestamp: request.SessionLoginTimestamp,
					ProfileCookie:         request.ProfileCookie,
					SessionCookie:         request.SessionCookie,
					User:                  profile.User,
					Category:              model.CategoryFailedMFA,
					Action:                model.Kill,
					Pid:                   request.RequestPid,
					OTPRequest:            request,
				}
				sshp.Forward(notification)
			} else {
				logrus.Printf("OTP authentication failure for user \"%s\", %v attempt(s) left", profile.User, model.MaxOTPFailures-profile.OTPFailedRequests)
			}
		}

		// send SIGUSR2
		if err := unix.Kill(int(request.RequestPid), syscall.SIGUSR2); err != nil {
			logrus.Warnf("failed to sent OTP authentication result to ssh-probe-auth: %v", err)
		}
	}
}
