// Copyright 2023 the cncf fuzzing authors
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

package v1

import (
	"testing"
	
	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func FuzzV1PolicyValidate(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		p := Policy{}
		ff.GenerateStruct(&p)
		_ = p.Validate(nil)
	})
}

var (
	path = field.NewPath("dummy")
)

func FuzzV1ImageVerification(f *testing.F) { 
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		iv := ImageVerification{}
		ff.GenerateStruct(&iv)
		iv.Validate(false, path)
	})
}

func FuzzV1MatchResources(f *testing.F) { 
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		mr := &MatchResources{}
		ff.GenerateStruct(&mr)
		mr.Validate(path, false, nil)
	})
}

func FuzzV1ClusterPolicy(f *testing.F) { 
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		cp := &ClusterPolicy{}
		ff.GenerateStruct(&cp)
		cp.HasAutoGenAnnotation()
		cp.HasMutateOrValidateOrGenerate()
		cp.HasMutate()
		cp.HasValidate()
		cp.HasGenerate()
		cp.HasVerifyImages()
		cp.AdmissionProcessingEnabled()
		cp.BackgroundProcessingEnabled()
		cp.Validate(nil)
	})
}
