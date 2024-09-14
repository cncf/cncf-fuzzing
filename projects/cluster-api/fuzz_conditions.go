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
	"testing"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
)

func FuzzPatchApply(f *testing.F) {
    f.Fuzz(func (t *testing.T, data []byte){
		fdp := fuzz.NewConsumer(data)
		getterBefore := &clusterv1.Cluster{}
		err := fdp.GenerateStruct(getterBefore)
		if err != nil {
			return
		}
		getterAfter := &clusterv1.Cluster{}
		err = fdp.GenerateStruct(getterAfter)
		if err != nil {
			return
		}

		setter := &clusterv1.Cluster{}
		err = fdp.GenerateStruct(setter)
		if err != nil {
			return
		}

		var options []ApplyOption
		err = fdp.CreateSlice(&options)
		if err != nil {
			return
		}
		patch, err := NewPatch(getterBefore, getterAfter)
		if err != nil {
			return
		}
		patch.Apply(setter, options...)
	})
}
