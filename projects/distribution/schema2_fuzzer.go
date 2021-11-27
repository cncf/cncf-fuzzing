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

package schema2

import (
	"context"

	"github.com/opencontainers/go-digest"

	"github.com/distribution/distribution/v3"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzUnmarshalJSON(data []byte) int {
	m := new(DeserializedManifest)
	err := m.UnmarshalJSON(b)
	if err != nil {
		return 0
	}
	b, err := m.MarshalSON()
	if err != nil {
		return 0
	}
	return 1
}

func FuzzNewManifestBuilder(data []byte) int {
	f := fuzz.NewConsumer(data)
	annotations := make(map[string]string)
	err := f.FuzzMap(&annotations)
	if err != nil {
		return 0
	}

	configJSON, err := f.GetBytes()
	if err != nil {
		return 0
	}

	configMediaType, err := f.GetString()
	if err != nil {
		return 0
	}

	bs := &mockBlobService{descriptors: make(map[digest.Digest]distribution.Descriptor)}
	builder := NewManifestBuilder(bs, configMediaType, configJSON)
	builder.Build(context.Background())
	return 1
}
