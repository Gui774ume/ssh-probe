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
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/dgryski/dgoogauth"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ssh-probe/pkg/utils"
)

type Action string

const (
	Allow Action = "allow"
	Block Action = "block"
	MFA   Action = "mfa"
	Kill  Action = "kill"
)

// Sanitize checks if the provided action is valid
func (a Action) Sanitize() error {
	switch a {
	case Block, MFA, Kill, Allow:
		return nil
	default:
		return fmt.Errorf("unknown action: %s", a)
	}
}

// KernelValue returns the kernel value of an action
func (a Action) KernelValue() uint8 {
	switch a {
	case Allow:
		return 0
	case Block:
		return 1
	case MFA:
		return 2
	case Kill:
		return 3
	default:
		return 0
	}
}

// ActionFromKernelValue returns an action from its kernel value
func ActionFromKernelValue(action uint8) Action {
	switch action {
	case 0:
		return Allow
	case 1:
		return Block
	case 2:
		return MFA
	case 3:
		return Kill
	default:
		return Allow
	}
}

type AccessRight string

const (
	Read  AccessRight = "read"
	Write AccessRight = "write"
	Any   AccessRight = "any"
)

// Sanitize checks if the provided access right is valid
func (ar AccessRight) Sanitize() error {
	switch ar {
	case Read, Write, Any:
		return nil
	default:
		return fmt.Errorf("unknown access right: %s", ar)
	}
}

// KernelValue returns the kernel value of an AccessRight
func (ar AccessRight) KernelValues() []uint8 {
	switch ar {
	case Read:
		return []uint8{1}
	case Write:
		return []uint8{2}
	case Any:
		return []uint8{1, 2}
	default:
		return []uint8{}
	}
}

type ActionKey struct {
	ProfileCookie uint32
	Category      Category
}

// GetActionKey returns a kernel ready representation of an ActionKey instance
func (ak ActionKey) GetActionKey() (unsafe.Pointer, error) {
	key, err := utils.InterfaceToBytes(ak)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&key[0]), nil
}

type Profiles struct {
	UnknownUserDefault Action     `yaml:"unknown_user_default"`
	UserProfiles       []*Profile `yaml:"user_profiles"`
}

func (p *Profiles) Sanitize() error {
	if err := p.UnknownUserDefault.Sanitize(); err != nil {
		return errors.Wrap(err, "invalid UnknownUserDefault action")
	}
	for _, profile := range p.UserProfiles {
		if err := profile.Sanitize(); err != nil {
			return errors.Wrapf(err, "invalid profile for user \"%s\"", profile.User)
		}
	}
	return nil
}

// UnknownUserProfile default unknown user profile
var UnknownUserProfile = Profile{
	User: "unknown_user",
}

type Profile struct {
	KernelCookie      uint32               `yaml:"-"`
	OTPConfig         *dgoogauth.OTPConfig `yaml:"-"`
	OTPFailedRequests int                  `yaml:"-"`

	User string `yaml:"user"`

	// Process monitoring
	Binaries             map[string]Action `yaml:"binaries"`
	UnknownBinaryDefault Action            `yaml:"unknown_binary_default"`

	// File Integrity Monitoring
	FIM               []*FilePolicy `yaml:"fim"`
	DeletionsAndMoves Action        `yaml:"deletions_and_moves"`
	UnknownFile       Action        `yaml:"unknown_file_default"`

	// Socket creation
	SocketCreation Action `yaml:"socket_creation"`

	// Privilege elevation
	PrivilegeElevation Action `yaml:"privilege_elevation"`

	// OS level protections
	OSLevelProtections Action `yaml:"os_level_protections"`

	// Process level protections
	ProcessLevelProtections Action `yaml:"process_level_protections"`

	// Performance monitoring
	PerformanceMonitoring Action `yaml:"performance_monitoring"`

	// Kill
	Kill Action `yaml:"kill"`
}

func (p *Profile) Sanitize() error {
	if len(p.User) == 0 {
		return fmt.Errorf("empty user")
	}

	// Process monitoring
	for path, action := range p.Binaries {
		if err := action.Sanitize(); err != nil {
			return errors.Wrapf(err, "invalid action for binary \"%s\"", path)
		}
	}

	// File Integrity Monitoring
	for _, policy := range p.FIM {
		if err := policy.Sanitize(); err != nil {
			return errors.Wrapf(err, "invalid policy for pattern \"%s\"", policy.Pattern)
		}
	}
	if err := p.DeletionsAndMoves.Sanitize(); err != nil {
		return errors.Wrap(err, "invalid DeletionsAndMoves action")
	}

	// Socket creation
	if err := p.SocketCreation.Sanitize(); err != nil {
		return errors.Wrap(err, "invalid SocketCreation action")
	}

	// Privilege elevation
	if err := p.PrivilegeElevation.Sanitize(); err != nil {
		return errors.Wrap(err, "invalid PrivilegeElevation action")
	}

	// OS level protections
	if err := p.OSLevelProtections.Sanitize(); err != nil {
		return errors.Wrap(err, "invalid OSLevelProtections action")
	}

	// Provess level protections
	if err := p.ProcessLevelProtections.Sanitize(); err != nil {
		return errors.Wrap(err, "invalid ProcessLevelProtections action")
	}

	// Performance monitoring
	if err := p.PerformanceMonitoring.Sanitize(); err != nil {
		return errors.Wrap(err, "invalid PerformanceMonitoring action")
	}

	// Kill
	if err := p.Kill.Sanitize(); err != nil {
		return errors.Wrap(err, "invalid Kill action")
	}
	return nil
}

// GetUserKey returns an unsafe pointer to a byte representation of the user name
func (p *Profile) GetUserKey() unsafe.Pointer {
	userB := [UsernameMaxLength]byte{}
	copy(userB[:], p.User)
	return unsafe.Pointer(&userB[0])
}

// BinaryPathKey is the key structure of the allowed_binaries map
type BinaryPathKey struct {
	Cookie uint32
	Path   [PathMax]byte
}

// GetBinaryPathKey returns an unsafe pointer to a BinaryPathKey instance
func GetBinaryPathKey(cookie uint32, path string) (unsafe.Pointer, error) {
	bpk := BinaryPathKey{
		Cookie: cookie,
	}
	copy(bpk.Path[:], path)
	key, err := utils.InterfaceToBytes(bpk)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&key[0]), nil
}

type InodeSelector struct {
	Inode         uint64
	ProfileCookie uint32
	AccessRight   uint8
}

// GetInodeSelector returns an unsafe pointer to a InodeSelector instance
func GetInodeSelector(inode uint64, cookie uint32, accessRight uint8) (unsafe.Pointer, error) {
	is := InodeSelector{
		Inode:         inode,
		ProfileCookie: cookie,
		AccessRight:   accessRight,
	}
	key, err := utils.InterfaceToBytes(is)
	if err != nil {
		return nil, err
	}
	return unsafe.Pointer(&key[0]), nil
}

type FilePolicy struct {
	Pattern     string            `yaml:"pattern"`
	AccessRight AccessRight       `yaml:"access_right"`
	Action      Action            `yaml:"action"`
	Inodes      map[uint64]string `yaml:"-"`
}

func (p *FilePolicy) Sanitize() error {
	if len(p.Pattern) == 0 {
		return fmt.Errorf("empty file policy pattern")
	}
	starCount := strings.Count(p.Pattern, "*")
	if starCount > 2 {
		return errors.New("file patterns can contain only 0, 1 or 2 stars")
	}
	if err := p.AccessRight.Sanitize(); err != nil {
		return err
	}
	if err := p.Action.Sanitize(); err != nil {
		return err
	}
	return nil
}

func (p *FilePolicy) ExpandPattern() error {
	switch strings.Count(p.Pattern, "*") {
	case 0:
		err := p.addPath(p.Pattern)
		if err != nil {
			return err
		}
	case 1:
		if err := p.expandOneStar(p.Pattern); err != nil {
			return err
		}
	case 2:
		if err := p.expandTwoStars(p.Pattern); err != nil {
			return err
		}
	}
	return nil
}

func (p *FilePolicy) addPath(path string) error {
	i, err := utils.GetInode(path)
	if err != nil {
		return err
	}
	logrus.Tracef("new path added: %s", path)
	if p.Inodes == nil {
		p.Inodes = make(map[uint64]string)
	}
	p.Inodes[i] = path
	return nil
}

func (p *FilePolicy) expandOneStar(pattern string) error {
	pathFragments := strings.Split(pattern, "*")
	if len(pathFragments) != 2 {
		return errors.New("invalid star count")
	}
	if pathFragments[1] == "" {
		err := filepath.Walk(pathFragments[0], func(walkPath string, fi os.FileInfo, err error) error {
			if err != nil {
				return errors.Wrapf(err, "couldn't walk through %s: %v", walkPath)
			}
			pathTmp := path.Join(walkPath, pathFragments[1])
			if _, err = os.Stat(pathTmp); err != nil {
				return err
			}
			if err = p.addPath(pathTmp); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		files, err := ioutil.ReadDir(pathFragments[0])
		if err != nil {
			return errors.Wrapf(err, "couldn't read %s: %v", pathFragments[0])
		}

		for _, f := range files {
			pathTmp := path.Join(pathFragments[0], f.Name(), pathFragments[1])
			if _, err = os.Stat(pathTmp); err != nil {
				continue
			}
			if err = p.addPath(pathTmp); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *FilePolicy) expandTwoStars(pattern string) error {
	pathFragments := strings.Split(pattern, "*")
	if len(pathFragments) != 3 {
		return errors.New("invalid star count")
	}
	files, err := ioutil.ReadDir(pathFragments[0])
	if err != nil {
		return errors.Wrapf(err, "couldn't read %s: %v", pathFragments[0])
	}

	for _, f := range files {
		pathTmp := path.Join(pathFragments[0], f.Name(), pathFragments[1])
		if _, err = os.Stat(pathTmp); err != nil {
			continue
		}
		oneStarPattern := path.Join(pathFragments[0], f.Name(), strings.TrimPrefix(pattern, pathFragments[0]+"*"))
		if err = p.expandOneStar(oneStarPattern); err != nil {
			return err
		}
	}
	return nil
}
