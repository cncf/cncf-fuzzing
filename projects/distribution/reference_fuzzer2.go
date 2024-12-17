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

package reference

import (
	"testing"
)

func FuzzWithNameAndWithTag(f *testing.F) {
	f.Fuzz(func(t *testing.T, name, tag string) {
		named, err := WithName(name)
		if err != nil {
			return
		}
		_, _ = WithTag(named, tag)
	})
}

func FuzzAllNormalizeApis(f *testing.F) {
	f.Fuzz(func(t *testing.T, ref string) {
		_, _ = ParseAnyReference(ref)
		n, err := ParseDockerRef(ref)
		if err != nil {
			return
		}
		_ = TagNameOnly(n)
	})
}
