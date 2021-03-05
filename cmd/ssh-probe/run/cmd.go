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
	"github.com/spf13/cobra"
)

// SSHProbe represents the base command of ssh-probe
var SSHProbeCmd = &cobra.Command{
	Use:   "ssh-probe",
	Short: "ssh-probe is a ssh session tracker based on eBPF, that can be used to mitigate the impact of stolen credentials",
	Long: `ssh-probe is a ssh session tracker based on eBPF, that can be used to mitigate the impact of stolen credentials

ssh-probe relies on eBPF to track ssh sessions at runtime. Stolen credentials impact by requiring 2FA on each
sensitive action, as defined in the profile of each user.
More information about the project can be found on github: https://github.com/Gui774ume/ssh-probe`,
	RunE:    runSSHProbeCmd,
	Example: "sudo ssh-probe --profiles /tmp/profiles",
}

var options CLIOptions

func init() {
	SSHProbeCmd.Flags().VarP(
		NewLogLevelSanitizer(&options.LogLevel),
		"log-level",
		"l",
		`log level, options: panic, fatal, error, warn, info, debug or trace`)
	SSHProbeCmd.Flags().VarP(
		NewPathSanitizer(&options.Profiles),
		"profiles",
		"p",
		`path to the file containing the security profiles for each user`)
	SSHProbeCmd.Flags().VarP(
		NewKernelNotifLevelSanitizer(&options.KernelNotificationLevel),
		"kernel-notification-level",
		"k",
		`minimum kernel notification level, options: allow, block, mfa, kill`)
	SSHProbeCmd.Flags().BoolVarP(
		&options.DisableGlobalMFAScope,
		"disable-mfa-global-scope",
		"s",
		false,
		`Disable MFA tokens with global scope`)
	SSHProbeCmd.Flags().StringVarP(
		&options.AgentURL,
		"agent-url",
		"a",
		"",
		`Datadog agent URL used to forward logs to Datadog`)
	SSHProbeCmd.MarkFlagRequired("profiles")
}
