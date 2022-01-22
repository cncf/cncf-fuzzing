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

package schema1

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/distribution/distribution/v3"
	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/reference"
	"github.com/docker/libtrust"
	"github.com/opencontainers/go-digest"
)

func FuzzSchema1Build(data []byte) int {

	pk, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		return 0
	}

	ref, err := reference.WithName("testrepo")
	if err != nil {
		return 0
	}
	ref, err = reference.WithTag(ref, "testtag")
	if err != nil {
		return 0
	}

	bs := &mockBlobService{descriptors: make(map[digest.Digest]distribution.Descriptor)}

	builder := NewConfigManifestBuilder(bs, pk, ref, data)

	_, _ = builder.Build(dcontext.Background())
	return 1
}

func FuzzSchema1Verify(data []byte) int {
	f := fuzz.NewConsumer(data)
	sm := &SignedManifest{}
	err := f.GenerateStruct(sm)
	if err != nil {
		return 0
	}
	_, _ = Verify(sm)
	return 1
}
