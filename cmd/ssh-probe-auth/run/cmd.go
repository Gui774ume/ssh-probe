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
	"time"

	"github.com/spf13/cobra"

	"github.com/Gui774ume/ssh-probe/pkg/model"
)

// SSHProbeAuthCmd represents the base command of ssh-probe-auth
var SSHProbeAuthCmd = &cobra.Command{
	Use:     "ssh-probe-auth",
	Short:   "ssh-probe-auth is used to authenticate your session with a one time password, in order to approve sensitive administrative operations",
	Long:    "ssh-probe-auth is used to authenticate your session with a one time password, in order to approve sensitive administrative operations",
	RunE:    runSSHProbeAuthCmd,
	Example: "ssh-probe-auth --timeout 30s",
}

var options CLIOptions

func init() {
	SSHProbeAuthCmd.Flags().DurationVarP(
		&options.Timeout,
		"timeout",
		"t",
		10*time.Second,
		fmt.Sprintf("MFA access timeout. Only values between 0 and %v are allowed.", model.MaxOTPTimeout))
	SSHProbeAuthCmd.Flags().VarP(
		NewScopeSanitizer(&options.Scope),
		"scope",
		"s",
		"scope of the MFA access. Options are: fim, process_monitoring, unknown_binary, socket_creation, deletes_and_moves, privilege_elevation, os_level_protections, process_level_protections, performance_monitoring, kill, global.")
}
