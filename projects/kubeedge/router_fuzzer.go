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

package utils

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzRuleContains(data []byte) int {
	f := fuzz.NewConsumer(data)
	path1, err := f.GetString()
	if err != nil {
		return 0
	}
	path2, err := f.GetString()
	if err != nil {
		return 0
	}
	RuleContains(path1, path2)
	return 1
}
