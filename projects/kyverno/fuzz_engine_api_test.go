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

package api

import (
	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	kubeutils "github.com/kyverno/kyverno/pkg/utils/kube"
	"testing"
)

func FuzzEngineResponse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)

		resource, err := ff.GetBytes()
		if err != nil {
			return
		}

		resourceUnstructured, err := kubeutils.BytesToUnstructured(resource)
		if err != nil {
			return
		}
		namespaceLabels := make(map[string]string)
		ff.FuzzMap(&namespaceLabels)
		resp := NewEngineResponse(*resourceUnstructured, nil, namespaceLabels)
		_ = resp.GetPatches()
		_ = resp.GetFailedRules()
		_ = resp.GetFailedRulesWithErrors()
		_ = resp.GetValidationFailureAction()
		_ = resp.GetSuccessRules()
	})
}
