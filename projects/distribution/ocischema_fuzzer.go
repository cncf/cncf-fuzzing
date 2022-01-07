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

package ocischema

import (
	"context"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/opencontainers/go-digest"

	"github.com/distribution/distribution/v3"
)

type fuzzMockBlobService struct {
	descriptors map[digest.Digest]distribution.Descriptor
}

func (bs *fuzzMockBlobService) Stat(ctx context.Context, dgst digest.Digest) (distribution.Descriptor, error) {
	if descriptor, ok := bs.descriptors[dgst]; ok {
		return descriptor, nil
	}
	return distribution.Descriptor{}, distribution.ErrBlobUnknown
}

func (bs *fuzzMockBlobService) Get(ctx context.Context, dgst digest.Digest) ([]byte, error) {
	panic("not implemented")
}

func (bs *fuzzMockBlobService) Open(ctx context.Context, dgst digest.Digest) (distribution.ReadSeekCloser, error) {
	panic("not implemented")
}

func (bs *fuzzMockBlobService) Put(ctx context.Context, mediaType string, p []byte) (distribution.Descriptor, error) {
	d := distribution.Descriptor{
		Digest:    digest.FromBytes(p),
		Size:      int64(len(p)),
		MediaType: "application/octet-stream",
	}
	bs.descriptors[d.Digest] = d
	return d, nil
}

func (bs *fuzzMockBlobService) Create(ctx context.Context, options ...distribution.BlobCreateOption) (distribution.BlobWriter, error) {
	panic("not implemented")
}

func (bs *fuzzMockBlobService) Resume(ctx context.Context, id string) (distribution.BlobWriter, error) {
	panic("not implemented")
}

func FuzzManifestBuilder(data []byte) int {
	annotations := make(map[string]string)

	f := fuzz.NewConsumer(data)
	err := f.FuzzMap(&annotations)
	if err != nil {
		return 0
	}

	imgJSON, err := f.GetBytes()
	if err != nil {
		return 0
	}
	configDigest := digest.FromBytes(imgJSON)

	bs := &fuzzMockBlobService{descriptors: make(map[digest.Digest]distribution.Descriptor)}
	builder := NewManifestBuilder(bs, imgJSON, annotations)
	_, err = builder.Build(context.Background())
	if err != nil {
		return 0
	}
	// Check that config exists in the config store:
	_, err = bs.Stat(context.Background(), configDigest)
	if err != nil {
		panic("config was not put in the blob store")
	}
	/*
		TODO:
		Get checks from: https://github.com/distribution/distribution/blob/1563384b69df9376389fe45ce949173a6383770a/manifest/ocischema/builder_test.go#L142
	*/
	return 1
}
