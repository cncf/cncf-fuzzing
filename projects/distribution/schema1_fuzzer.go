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
	"encoding/json"
	"time"
	"github.com/distribution/distribution/v3"
	dcontext "github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/reference"
	"github.com/docker/libtrust"
	"github.com/opencontainers/go-digest"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzSchema1Build(data []byte) int {
	f := fuzz.NewConsumer(data)
	imgJSON, err := f.GetBytes()
	if err != nil {
		return 0
	}

	type imageRootFS struct {
		Type      string   `json:"type"`
		DiffIDs   []diffID `json:"diff_ids,omitempty"`
		BaseLayer string   `json:"base_layer,omitempty"`
	}

	type imageHistory struct {
		Created    time.Time `json:"created"`
		Author     string    `json:"author,omitempty"`
		CreatedBy  string    `json:"created_by,omitempty"`
		Comment    string    `json:"comment,omitempty"`
		EmptyLayer bool      `json:"empty_layer,omitempty"`
	}

	type imageConfig struct {
		RootFS       *imageRootFS   `json:"rootfs,omitempty"`
		History      []imageHistory `json:"history,omitempty"`
		Architecture string         `json:"architecture,omitempty"`
	}

	// Check the imgJSON before we proceed
	var img imageConfig
	if err := json.Unmarshal(imgJSON, &img); err != nil {
		return 0
	}

	if len(img.History) == 0 {
		return 0
	}
	if len(img.RootFS.DiffIDs) == 0 {
		return 0
	}

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

	builder := NewConfigManifestBuilder(bs, pk, ref, imgJSON)

	for i:=0;i<len(img.RootFS.DiffIDs)%5;i++ {
		d := distribution.Descriptor{}
		err = f.GenerateStruct(&d)
		if err != nil {
			return 0
		}
		digestBytes, err := f.GetBytes()
		if err != nil {
			return 0
		}
		d.Digest = digest.FromBytes(digestBytes)
		if err := builder.AppendReference(d); err != nil {
			return 0
		}
	}

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
