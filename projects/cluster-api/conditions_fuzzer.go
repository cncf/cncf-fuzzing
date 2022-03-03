// Copyright 2022 ADA Logics Ltd
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

package conditions

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
)

func FuzzPatchApply(data []byte) int {
	f := fuzz.NewConsumer(data)
	getterBefore := &clusterv1.Cluster{}
	err := f.GenerateStruct(getterBefore)
	if err != nil {
		return 0
	}
	getterAfter := &clusterv1.Cluster{}
	err = f.GenerateStruct(getterAfter)
	if err != nil {
		return 0
	}

	setter := &clusterv1.Cluster{}
	err = f.GenerateStruct(setter)
	if err != nil {
		return 0
	}

	var options []ApplyOption
	err = f.CreateSlice(&options)
	if err != nil {
		return 0
	}

	patch := NewPatch(getterBefore, getterAfter)
	_ = patch.Apply(setter, options...)
	return 1
}
