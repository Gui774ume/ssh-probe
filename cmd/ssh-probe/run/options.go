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

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ssh-probe/pkg/model"
)

// CLIOptions are the command line options of ssh-probe
type CLIOptions struct {
	KernelNotificationLevel model.Action
	LogLevel                logrus.Level
	Profiles                string
	DisableGlobalMFAScope   bool
	AgentURL                string
}

// LogLevelSanitizer is a log level sanitizer that ensures that the provided log level exists
type LogLevelSanitizer struct {
	logLevel *logrus.Level
}

// NewLogLevelSanitizer creates a new instance of LogLevelSanitizer. The sanitized level will be written in the provided
// logurs level
func NewLogLevelSanitizer(sanitizedLevel *logrus.Level) *LogLevelSanitizer {
	*sanitizedLevel = logrus.InfoLevel
	return &LogLevelSanitizer{
		logLevel: sanitizedLevel,
	}
}

func (lls *LogLevelSanitizer) String() string {
	return fmt.Sprintf("%v", *lls.logLevel)
}

func (lls *LogLevelSanitizer) Set(val string) error {
	sanitized, err := logrus.ParseLevel(val)
	if err != nil {
		return err
	}
	*lls.logLevel = sanitized
	return nil
}

func (lls *LogLevelSanitizer) Type() string {
	return "string"
}

// PathSanitizer is a path sanitizer that ensures that the provided path exists
type PathSanitizer struct {
	path *string
}

// NewPathSanitizer creates a new instance of PathSanitizer. The sanitized path will be written in the provided string
func NewPathSanitizer(sanitizedPath *string) *PathSanitizer {
	return &PathSanitizer{
		path: sanitizedPath,
	}
}

func (ps *PathSanitizer) String() string {
	return fmt.Sprintf("%v", *ps.path)
}

func (ps *PathSanitizer) Set(val string) error {
	if len(val) == 0 {
		return errors.New("empty path")
	}
	if _, err := os.Stat(val); err != nil {
		return err
	}
	*ps.path = val
	return nil
}

func (ps *PathSanitizer) Type() string {
	return "string"
}

type KernelNotifLevelSanitizer struct {
	level *model.Action
}

// NewKernelNotifLevelSanitizer creates a new instance of KernelNotifLevelSanitizer.
func NewKernelNotifLevelSanitizer(sanitizedLevel *model.Action) *KernelNotifLevelSanitizer {
	*sanitizedLevel = model.MFA
	return &KernelNotifLevelSanitizer{
		level: sanitizedLevel,
	}
}

func (knls *KernelNotifLevelSanitizer) String() string {
	return fmt.Sprintf("%v", *knls.level)
}

func (knls *KernelNotifLevelSanitizer) Set(val string) error {
	action := model.Action(val)
	if err := action.Sanitize(); err != nil {
		return err
	}
	*knls.level = action
	return nil
}

func (knls *KernelNotifLevelSanitizer) Type() string {
	return "string"
}
