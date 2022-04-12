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
	"github.com/distribution/distribution/v3/digestset"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzWithNameAndWithTag(data []byte) int {
	f := fuzz.NewConsumer(data)
	name, err := f.GetString()
	if err != nil {
		return 0
	}
	named, err := WithName(name)
	if err != nil {
		return 0
	}
	tag, err := f.GetString()
	if err != nil {
		return 0
	}
	_, _ = WithTag(named, tag)
	return 1
}

func FuzzAllNormalizeApis(data []byte) int {
	f := fuzz.NewConsumer(data)
	ref, err := f.GetString()
	if err != nil {
		return 0
	}
	n, err := ParseDockerRef(ref)
	_ = TagNameOnly(n)
	ref, err = f.GetString()
	if err != nil {
		return 0
	}
	_, _ = ParseAnyReference(ref)
	ds := &digestset.Set{}
	err = f.GenerateStruct(ds)
	if err != nil {
		return 0
	}
	ref, err = f.GetString()
	if err != nil {
		return 0
	}
	_, _ = ParseAnyReferenceWithSet(ref, ds)
	return 1
}

