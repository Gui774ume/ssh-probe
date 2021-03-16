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
	"C"
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/Gui774ume/ssh-probe/pkg/utils"
)

type Resolver interface {
	CacheInode(path string) (uint64, error)
	ResolveInode(ino uint64) (string, bool)
}

type Notification struct {
	Timestamp             time.Time `json:"timestamp"`
	SessionLoginTimestamp time.Time `json:"session_login_timestamp"`
	User                  string    `json:"profile_user"`
	ProfileCookie         uint32    `json:"profile_cookie"`
	SessionCookie         uint32    `json:"session_cookie"`
	Category              Category  `json:"category"`
	Action                Action    `json:"action"`
	Pid                   uint32    `json:"pid"`
	Tid                   uint32    `json:"tid"`
	Comm                  string    `json:"comm"`

	Syscall    *Syscall    `json:"syscall,omitempty"`
	BinaryPath *BinaryPath `json:"binary_path,omitempty"`
	FIM        *FIM        `json:"fim,omitempty"`
	OTPRequest *OTPRequest `json:"otp,omitempty"`
}

func (n *Notification) String() string {
	p := fmt.Sprintf(
		"%s session:%v user:%s category:%s pid:%d comm:%s",
		strings.ToUpper(string(n.Action)),
		n.SessionCookie,
		n.User,
		n.Category,
		n.Pid,
		n.Comm)

	switch n.Category {
	case CategorySocketCreation, CategoryDeletionsAndMoves, CategoryPrivilegeElevation, CategoryOSLevelProtections, CategoryProcessLevelProtections, CategoryPerformanceMonitoring, CategoryKill:
		p = fmt.Sprintf("%s %s", p, n.Syscall.String())
	case CategoryProcessMonitoring:
		p = fmt.Sprintf("%s %s", p, n.BinaryPath.String())
	case CategoryFim:
		p = fmt.Sprintf("%s %s %s", p, n.Syscall.String(), n.FIM.String())
	}
	return p
}

func (n *Notification) UnmarshalBinary(data []byte, bootTime time.Time, resolver Resolver) (int, error) {
	if len(data) < 32 {
		return 0, ErrNotEnoughData
	}
	n.Timestamp = bootTime.Add(time.Duration(utils.ByteOrder.Uint64(data[0:8])) * time.Nanosecond)
	n.SessionLoginTimestamp = bootTime.Add(time.Duration(utils.ByteOrder.Uint64(data[8:16])) * time.Nanosecond)
	n.ProfileCookie = utils.ByteOrder.Uint32(data[16:20])
	n.SessionCookie = utils.ByteOrder.Uint32(data[20:24])
	n.Category = Category(utils.ByteOrder.Uint32(data[24:28]))
	n.Action = ActionFromKernelValue(uint8(utils.ByteOrder.Uint32(data[28:32])))
	n.Pid = utils.ByteOrder.Uint32(data[32:36])
	n.Tid = utils.ByteOrder.Uint32(data[36:40])
	n.Comm = bytes.NewBuffer(bytes.Trim(data[40:56], "\x00")).String()

	cursor := 56

	switch n.Category {
	case CategorySocketCreation, CategoryDeletionsAndMoves, CategoryPrivilegeElevation, CategoryOSLevelProtections, CategoryProcessLevelProtections, CategoryPerformanceMonitoring, CategoryKill:
		n.Syscall = &Syscall{}
		return n.Syscall.UnmarshalBinary(data[cursor:])
	case CategoryProcessMonitoring:
		n.BinaryPath = &BinaryPath{}
		return n.BinaryPath.UnmarshalBinary(data[cursor:])
	case CategoryFim:
		n.FIM = &FIM{}
		read, err := n.FIM.UnmarshalBinary(data[cursor:], resolver)
		if err != nil {
			return 0, err
		}
		cursor += read
		n.Syscall = &Syscall{}
		return n.Syscall.UnmarshalBinary(data[cursor:])
	}
	return 32, nil
}

type Syscall struct {
	ID   uint32 `json:"id"`
	Name string `json:"name"`
}

func (sn *Syscall) String() string {
	return fmt.Sprintf("syscall:%d syscall_name:%s", sn.ID, sn.Name)
}

func (sn *Syscall) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, ErrNotEnoughData
	}
	sn.ID = utils.ByteOrder.Uint32(data[0:4])
	sn.Name = GetSyscallName(sn.ID)
	return 4, nil
}

type BinaryPath struct {
	ProfileCookie uint32 `json:"-"`
	BinaryPath    string `json:"binary_path"`
}

func (bp *BinaryPath) String() string {
	return fmt.Sprintf("binary_path:%s", bp.BinaryPath)
}

func (bp *BinaryPath) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, ErrNotEnoughData
	}
	bp.ProfileCookie = utils.ByteOrder.Uint32(data[0:4])
	bp.BinaryPath = bytes.NewBuffer(bytes.Trim(data[4:], "\x00")).String()
	return len(data), nil
}

type FIM struct {
	Inode uint64 `json:"inode"`
	Path  string `json:"path"`
}

func (f *FIM) String() string {
	return fmt.Sprintf("inode:%d path:%s", f.Inode, f.Path)
}

func (f *FIM) UnmarshalBinary(data []byte, resolver Resolver) (int, error) {
	if len(data) < 8 {
		return 0, ErrNotEnoughData
	}
	f.Inode = utils.ByteOrder.Uint64(data[0:8])
	f.Path, _ = resolver.ResolveInode(f.Inode)
	return 8, nil
}
