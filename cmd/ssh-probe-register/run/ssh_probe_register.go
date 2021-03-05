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
	"encoding/base32"
	"fmt"
	"io/ioutil"
	"net/url"
	"rsc.io/qr"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Gui774ume/ssh-probe/pkg/utils"
)

func runSSHProbeRegisterCmd(cmd *cobra.Command, args []string) error {
	// Set log level
	logrus.SetLevel(logrus.DebugLevel)

	// Generate random secret instead of using the test value above.
	secret, err := utils.NewMFASecret()
	if err != nil {
		logrus.Fatalf("failed to generate a new MFA secret: %v", err)
	}
	secretBase32 := base32.StdEncoding.EncodeToString(secret)
	logrus.Infof("new secret generated for \"%s\": %v (base32: %v)", options.User, secret, secretBase32)
	logrus.Infof("export the following environment variable to ssh-probe (comma separated list): SSH_PROBE_SECRETS=\"%s:%s\"", options.User, secretBase32)

	// Generate MFA URL
	url, err := generateURL(secretBase32)
	if err != nil {
		logrus.Fatalf("failed to generate the MFA URL: %v", err)
	}
	logrus.Infof("MFA URL: %s", url)

	if len(options.Output) > 0 {
		if err := generateQRCode(url); err != nil {
			logrus.Fatalf("failed to generate QR code: %v", err)
		}
	}
	logrus.Infof("QR code was generated in %s. Please scan it into MFA app.\n", options.Output)
	return nil
}

func generateURL(secret string) (string, error) {
	account := fmt.Sprintf("%s@ssh-probe.com", options.User)
	issuer := "SSHProbe"

	URL, err := url.Parse("otpauth://totp")
	if err != nil {
		return "", err
	}

	URL.Path += "/" + url.PathEscape(issuer) + ":" + url.PathEscape(account)

	params := url.Values{}
	params.Add("secret", secret)
	params.Add("issuer", issuer)

	URL.RawQuery = params.Encode()
	return URL.String(), nil
}

func generateQRCode(url string) error {
	code, err := qr.Encode(url, qr.Q)
	if err != nil {
		return err
	}
	b := code.PNG()
	err = ioutil.WriteFile(options.Output, b, 0600)
	if err != nil {
		return err
	}
	return nil
}
