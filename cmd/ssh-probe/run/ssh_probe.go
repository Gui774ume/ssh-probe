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
	"github.com/pkg/errors"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	ssh_probe "github.com/Gui774ume/ssh-probe/pkg/ssh-probe"
)

func runSSHProbeCmd(cmd *cobra.Command, args []string) error {
	// Set log level
	logrus.SetLevel(options.LogLevel)

	if len(os.Getenv("SSH_PROBE_SECRETS")) == 0 {
		return errors.New("couldn't find any secret in SSH_PROBE_SECRETS environment variable")
	}

	// creates a new instance of ssh-probe
	sshp, err := ssh_probe.NewSSHProbe(options.Profiles, options.KernelNotificationLevel, options.DisableGlobalMFAScope, options.AgentURL)
	if err != nil {
		logrus.Fatalf("%v", err)
	}
	if err := sshp.Start(); err != nil {
		logrus.Fatalf("%v", err)
	}

	logrus.Info("ssh-probe successfully started")
	wait()

	// stops ssh-probe
	if err := sshp.Stop(); err != nil {
		logrus.Fatalf("%v", err)
	}
	logrus.Info("ssh-probe stopped")
	return nil
}

// wait stops the main goroutine until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
