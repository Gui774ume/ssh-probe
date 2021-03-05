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

	"github.com/Gui774ume/ssh-probe/pkg/model"
)

// CLIOptions are the command line options of ssh-probe
type CLIOptions struct {
	Timeout time.Duration
	Scope   model.Category
}

type ScopeSanitizer struct {
	scope *model.Category
}

// NewKernelNotifLevelSanitizer creates a new instance of KernelNotifLevelSanitizer.
func NewScopeSanitizer(sanitizedScope *model.Category) *ScopeSanitizer {
	*sanitizedScope = model.CategoryGlobal
	return &ScopeSanitizer{
		scope: sanitizedScope,
	}
}

func (ss *ScopeSanitizer) String() string {
	return fmt.Sprintf("%s", *ss.scope)
}

func (ss *ScopeSanitizer) Set(val string) error {
	category, err := model.GetCategory(val)
	if err != nil {
		return err
	}
	*ss.scope = category
	return nil
}

func (ss *ScopeSanitizer) Type() string {
	return "string"
}
