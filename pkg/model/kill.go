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
	"time"

	"github.com/Gui774ume/ssh-probe/pkg/utils"
)

type KillRequest struct {
	Timestamp             time.Time
	SessionLoginTimestamp time.Time
	ProfileCookie         uint32
	SessionCookie         uint32
	SessionInitPid        uint32
}

func (kr *KillRequest) UnmarshalBinary(data []byte, bootTime time.Time) (int, error) {
	if len(data) < 20 {
		return 0, ErrNotEnoughData
	}
	kr.Timestamp = bootTime.Add(time.Duration(utils.ByteOrder.Uint64(data[0:8])) * time.Nanosecond)
	kr.SessionLoginTimestamp = bootTime.Add(time.Duration(utils.ByteOrder.Uint64(data[8:16])) * time.Nanosecond)
	kr.ProfileCookie = utils.ByteOrder.Uint32(data[16:20])
	kr.SessionInitPid = utils.ByteOrder.Uint32(data[20:24])
	kr.SessionCookie = utils.ByteOrder.Uint32(data[24:28])
	return 28, nil
}
