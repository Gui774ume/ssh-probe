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
package model

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/Gui774ume/ssh-probe/pkg/utils"
	"github.com/pkg/errors"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// OTPRequest is used to represent an OTP request from the ssh-probe-auth
type OTPRequest struct {
	Timestamp             time.Time            `json:"-"`
	SessionLoginTimestamp time.Time            `json:"-"`
	ProfileCookie         uint32               `json:"-"`
	SessionCookie         uint32               `json:"-"`
	SessionInitPid        uint32               `json:"-"`
	RequestPid            uint32               `json:"-"`
	OTPRequest            string               `json:"-"`
	OTPRequestRaw         [OTPRequestSize]byte `json:"-"`

	OTPTimeout time.Duration `json:"timeout"`
	OTPToken   string        `json:"-"`
	OTPScope   Category      `json:"scope"`
}

// UnmarshalBinary parses raw bytes into an OTPRequest instance
func (or *OTPRequest) UnmarshalBinary(data []byte, bootTime time.Time) (int, error) {
	if len(data) < 24+OTPRequestSize {
		return 0, ErrNotEnoughData
	}
	or.Timestamp = bootTime.Add(time.Duration(utils.ByteOrder.Uint64(data[0:8])) * time.Nanosecond)
	or.SessionLoginTimestamp = bootTime.Add(time.Duration(utils.ByteOrder.Uint64(data[8:16])) * time.Nanosecond)
	or.ProfileCookie = utils.ByteOrder.Uint32(data[16:20])
	or.SessionInitPid = utils.ByteOrder.Uint32(data[20:24])
	or.RequestPid = utils.ByteOrder.Uint32(data[24:28])
	or.SessionCookie = utils.ByteOrder.Uint32(data[28:32])
	if err := binary.Read(bytes.NewBuffer(data[32:32+OTPRequestSize]), utils.ByteOrder, &or.OTPRequestRaw); err != nil {
		return 32, err
	}
	or.OTPRequest = string(bytes.Trim(or.OTPRequestRaw[:], "\x00"))
	// Extract token and requested access timeout
	if err := or.ParseOTPRequest(); err != nil {
		return 32 + OTPRequestSize, err
	}
	return 32 + OTPRequestSize, nil
}

// ParseOTPRequest parses an OTP request to extract the timeout and the one time password
func (or *OTPRequest) ParseOTPRequest() error {
	var err error

	// Parse scope
	req := strings.Replace(or.OTPRequest, "otp://", "", 1)
	splitScope := strings.Split(req, ":")
	if len(splitScope) != 2 {
		return fmt.Errorf("invalid OTP request format: %s", or.OTPRequest)
	}
	or.OTPScope, err = GetCategory(splitScope[0])
	if err != nil {
		return errors.Wrapf(err, "invalid OTP request %s", or.OTPRequest)
	}

	// Parse timeout
	splitTimeout := strings.Split(splitScope[1], "@")
	if len(splitTimeout) != 2 {
		return fmt.Errorf("invalid OTP request format: %s", or.OTPRequest)
	}
	timeoutMill, err := strconv.Atoi(splitTimeout[0])
	if err != nil {
		return fmt.Errorf("invalid OTP timeout format: %s", or.OTPRequest)
	}
	or.OTPTimeout = time.Duration(timeoutMill) * time.Microsecond

	// Parse token
	or.OTPToken = splitTimeout[1]
	return nil
}

type MFASelector struct {
	ProfileCookie uint32
	SessionCookie uint32
	Scope         Category
}

// GetMFASelectorKey returns a kernel ready representation of an MFASelector instance
func (mfa MFASelector) GetMFASelectorKey() (unsafe.Pointer, error) {
	key, err := utils.InterfaceToBytes(mfa)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&key[0]), nil
}
