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
	"testing"

	"github.com/opencontainers/go-digest"

	"github.com/distribution/distribution/v3"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzUnmarshalJSON(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		m := new(DeserializedManifest)
		err := m.UnmarshalJSON(b)
		if err != nil {
			return
		}
		b, err := m.MarshalSON()
		if err != nil {
			return
		}
	})
}

func FuzzNewManifestBuilder(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)
		annotations := make(map[string]string)
		err := f.FuzzMap(&annotations)
		if err != nil {
			return 0
		}

		configJSON, err := fdp.GetBytes()
		if err != nil {
			return
		}

		configMediaType, err := fdp.GetString()
		if err != nil {
			return
		}

		bs := &mockBlobService{descriptors: make(map[digest.Digest]distribution.Descriptor)}
		builder := NewManifestBuilder(bs, configMediaType, configJSON)
		builder.Build(context.Background())
	})
}
