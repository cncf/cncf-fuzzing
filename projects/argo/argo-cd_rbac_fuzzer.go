// Copyright 2021 ADA Logics Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package rbac

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzLoadPolicy(data []byte) int {
	f := fuzz.NewConsumer(data)
	m := model.Model{}
	err := f.GenerateStruct(&m)
	if err != nil {
		return 0
	}
	builtinPolicy, err := f.GetString()
	if err != nil {
		return 0
	}
	userDefinedPolicy, err := f.GetString()
	if err != nil {
		return 0
	}
	runtimePolicy, err := f.GetString()
	if err != nil {
		return 0
	}
	argocdAdapter := newAdapter(builtinPolicy, userDefinedPolicy, runtimePolicy)
	argocdAdapter.LoadPolicy(m)
	return 1
}

func FuzzEnforce(data []byte) int {
	defer func() { recover() }()
	f := fuzz.NewConsumer(data)
	builtinPolicy, err := f.GetString()
	if err != nil {
		return 0
	}
	userPolicy, err := f.GetString()
	if err != nil {
		return 0
	}
	runtimePolicy, err := f.GetString()
	if err != nil {
		return 0
	}
	sub, err := f.GetString()
	if err != nil {
		return 0
	}
	resource, err := f.GetString()
	if err != nil {
		return 0
	}
	action, err := f.GetString()
	if err != nil {
		return 0
	}

	adapter := newAdapter(builtinPolicy, userPolicy, runtimePolicy)
	builtInModel := newBuiltInModel()
	enf, err := casbin.NewEnforcer(builtInModel, adapter)
	if err != nil {
		return 0
	}
	enf.Enforce(sub, resource, action)
	return 1
}
