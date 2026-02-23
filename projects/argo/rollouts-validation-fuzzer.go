// Copyright 2025 the cncf-fuzzing authors.
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

package validation

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
)

func FuzzValidateRollout(data []byte) int {
	f := fuzz.NewConsumer(data)
	rollout := &v1alpha1.Rollout{}
	err := f.GenerateStruct(rollout)
	if err != nil {
		return 0
	}
	_ = ValidateRollout(rollout)
	return 1
}
