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
package run

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Gui774ume/ssh-probe/pkg/model"
)

var (
	sshProbeTimeout = 10 * time.Second
)

func runSSHProbeAuthCmd(cmd *cobra.Command, args []string) error {
	stop := make(chan os.Signal, 1)
	success := make(chan os.Signal, 1)
	failed := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, os.Kill)
	signal.Notify(success, syscall.SIGUSR1)
	signal.Notify(failed, syscall.SIGUSR2)
	var timer *time.Timer

	// Set log level
	logrus.SetLevel(logrus.DebugLevel)

	// check timeout value
	if options.Timeout > model.MaxOTPTimeout || options.Timeout < 0 {
		return errors.New("Timeout must be between 0 and 10 minutes")
	}

	// scan for otp token
	for {
		var token string
		logrus.Info("Enter your one time password (or q to quit): ")
		_, err := fmt.Scanln(&token)
		if err != nil {
			return errors.Wrap(err, "Failed to read user input")
		}
		if token == "q" {
			return nil
		}

		// check OTP
		if err := checkOTP(token, options.Timeout.Microseconds(), options.Scope); err != nil {
			logrus.Error(err)
			return nil
		}

		// Wait for an answer from ssh-probe
		timer = time.NewTimer(sshProbeTimeout)
		select {
		case <-timer.C:
			logrus.Error("ssh-probe took too long to answer")
			return nil
		case <-stop:
			fmt.Println()
			return nil
		case <-success:
			logrus.Infof("Authentication successful (token expires in %v)", options.Timeout)
			return nil
		case <-failed:
			logrus.Warn("Authentication failed, try again ...")
			continue
		}
	}
}

func checkOTP(token string, timeout int64, scope model.Category) error {
	// craft a special stat request that ssh-probe will catch to check the OTP
	otpStr := fmt.Sprintf("otp://%s:%v@%s", scope.String(), timeout, token)
	if _, err := os.Stat(otpStr); err != nil {
		if os.IsNotExist(err) {
			return errors.New("ssh-probe didn't answer properly. Is ssh-probe running ?")
		}
	}
	return nil
}
