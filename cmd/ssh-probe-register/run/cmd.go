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
var SSHProbeRegisterCmd = &cobra.Command{
	Use:     "ssh-probe-register",
	Short:   "ssh-probe-register is used to generate MFA secrets and QR codes so that you can configure an OTP app with ssh-probe",
	Long:    "ssh-probe-register is used to generate MFA secrets and QR codes so that you can configure an OTP app with ssh-probe",
	RunE:    runSSHProbeRegisterCmd,
	Example: "ssh-probe-register -o /tmp/ -u vagrant",
}

var options CLIOptions

func init() {
	SSHProbeRegisterCmd.Flags().StringVarP(
		&options.Output,
		"output",
		"o",
		"/tmp/qr.png",
		"Output .png file for the QR code image.")
	SSHProbeRegisterCmd.Flags().StringVarP(
		&options.User,
		"user",
		"u",
		"",
		"Username for which the secret is being generated.")
	SSHProbeRegisterCmd.MarkFlagRequired("user")
}
