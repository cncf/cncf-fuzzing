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

package inject

import (
	l5dcharts "github.com/linkerd/linkerd2/pkg/charts/linkerd2"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzInject(data []byte) int {
	f := fuzz.NewConsumer(data)
	yamlBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}

	v := &l5dcharts.Values{}
	err = f.GenerateStruct(v)
	if err != nil {
		return 0
	}
	conf := NewResourceConfig(v, OriginUnknown, "linkerd")
	_, _ = conf.ParseMetaAndYAML(yamlBytes)
	injectProxy, err := f.GetBool()
	if err != nil {
		return 0
	}
	_, _ = conf.GetPodPatch(injectProxy)
	_, _ = conf.CreateOpaquePortsPatch()

	report := &Report{}
	err = f.GenerateStruct(report)
	if err == nil {
		_, _ = conf.Uninject(report)
	}
	return 1
}
