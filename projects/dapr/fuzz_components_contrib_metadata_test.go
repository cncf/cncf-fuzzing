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

package metadata

import (
	"testing"
	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
)

type FuzzStruct struct {
	Name1 string
	Name2 string
	Name3 string
	Int1 int
	Int2 int
	Float1 float64
}

func FuzzDecodeMetadata(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		m := make(map[string]string)
		ff.FuzzMap(&m)
		if len(m) == 0 {
			return
		}
		fs := &FuzzStruct{}
		DecodeMetadata(m, fs)
	})
}