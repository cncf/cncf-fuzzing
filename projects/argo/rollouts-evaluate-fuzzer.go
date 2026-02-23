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

package evaluate

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzEvalCondition(data []byte) int {
	f := fuzz.NewConsumer(data)

	condition, err := f.GetString()
	if err != nil {
		return 0
	}

	// Test with string result value
	strVal, err := f.GetString()
	if err != nil {
		return 0
	}
	_, _ = EvalCondition(strVal, condition)

	// Test with int result value
	intVal, err := f.GetInt()
	if err == nil {
		_, _ = EvalCondition(intVal, condition)
	}

	return 1
}
