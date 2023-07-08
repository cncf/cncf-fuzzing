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

package graphql

import (
	"regexp"
	"strings"
	"testing"
)

func FuzzGraphqlRETest(f *testing.F) {
	f.Fuzz(func(t *testing.T, requestString, requestKey string) {
		re, err := regexp.Compile(`(?m)` + requestKey + `\b`)
		if err != nil {
			return
		}
		requestString = strings.TrimSpace(requestString)
		_ = re.FindAllStringIndex(requestString, 1)
	})
}
