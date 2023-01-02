// Copyright 2023 the cncf-fuzzing authors
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

package configmaps

import (
	"context"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"testing"
	stdTesting "testing"
	admissionv1 "k8s.io/api/admission/v1"
)

func FuzzAdmit(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		req := &admissionv1.AdmissionRequest{}
		ff := fuzz.NewConsumer(data)
		ff.GenerateStruct(req)

		stdT := &stdTesting.T{}
		_, ac := newNonRunningTestConfigValidationController(stdT)
		ac.Admit(context.Background(), req)
	})
}
