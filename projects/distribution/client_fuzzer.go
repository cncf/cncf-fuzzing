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

package client

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/docker/libtrust"
	"github.com/opencontainers/go-digest"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/manifest"
	"github.com/distribution/distribution/v3/manifest/schema2"
	"github.com/distribution/distribution/v3/testutil"
	"github.com/distribution/reference"
)

var (
	fuzzRepo = "test.example.com/repo1"
)

func FuzzBlobServeBlob(data []byte) int {
	fdp := fuzz.NewConsumer(data)
	digestBytes, err := fdp.GetBytes()
	if err != nil {
		return 0
	}
	if len(digestBytes) == 0 {
		return 0
	}
	dgst := digest.FromBytes(digestBytes)
	err = dgst.Validate()
	if err != nil {
		return 0
	}

	var m testutil.RequestResponseMap
	addTestFetch("test.example.com/repo1", dgst, digestBytes, &m)

	e, c := testServerForFuzz(m)
	defer c()

	ctx := context.Background()
	repo, _ := reference.WithName(fuzzRepo)
	r, err := NewRepository(repo, e, nil)
	if err != nil {
		return 0
	}
	l := r.Blobs(ctx)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	err = l.ServeBlob(ctx, resp, req, dgst)
	if err != nil {
		return 0
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0
	}
	if string(body) != string(digestBytes) {
		panic(fmt.Sprintf("Unexpected response body. Got %q, expected %q", string(body), string(digestBytes)))
	}

	expectedHeaders := []struct {
		Name  string
		Value string
	}{
		{Name: "Content-Length", Value: fmt.Sprintf("%d", len(digestBytes))},
		{Name: "Content-Type", Value: "application/octet-stream"},
		{Name: "Docker-Content-Digest", Value: dgst.String()},
		{Name: "Etag", Value: dgst.String()},
	}

	for _, h := range expectedHeaders {
		if resp.Header().Get(h.Name) != h.Value {
			//fmt.Printf("Unexpected %s. Got %s, expected %s\n", h.Name, resp.Header().Get(h.Name), h.Value)
			panic(fmt.Sprintf("Unexpected %s. Got %s, expected %s", h.Name, resp.Header().Get(h.Name), h.Value))
		}
	}
	return 1
}

func newRandomBlobForFuzz(f *fuzz.ConsumeFuzzer) (digest.Digest, []byte, error) {
	b, err := fdp.GetBytes()
	if err != nil {
		return digest.FromBytes([]byte("0")), nil, err
	}
	return digest.FromBytes(b), b, nil
}

func newRandomOCIManifestForFuzz(f *fuzz.ConsumeFuzzer, name reference.Named, tag string) (*schema2.SignedManifest, digest.Digest, []byte, error) {
	blobCount, err := fdp.GetUint8()
	if err != nil {
		return nil, digest.FromBytes([]byte("fuzz")), err
	}
	layers := make([]v1.Descriptor, blobCount%10)
	for i := 0; i < blobCount; i++ {
		dgst, blob := newRandomBlobForFuzz(f)
		layers[i] = v1.Descriptor{
			MediaType: v1.MediaTypeImageLayer,
			Digest:    dgst,
			Size:      int64(len(blob)),
		}
	}

	m := ocischema.Manifest{}
	fdp.GenerateStruct(&m)
	m.Layers = layers

	sm, err := ocischema.FromStruct(m)
	if err != nil {
		t.Fatal(err)
	}

	_, payload, _ := sm.Payload()

	return &m, digest.FromBytes(payload), payload
}

func testServerForFuzz(rrm testutil.RequestResponseMap) (string, func()) {
	h := testutil.NewHandler(rrm)
	s := httptest.NewServer(h)
	return s.URL, s.Close
}

func FuzzRegistryClient(data []byte) int {
	var m testutil.RequestResponseMap

	f := fuzz.NewConsumer(data)
	noOfRRMappings, err := fdp.GetUint8()
	if err != nil {
		return 0
	}

	for i := 0; i < noOfRRMappings%10; i++ {

	}

	e, c := testServer(m)
	defer c()

	repo, _ := reference.WithName("test.example.com/uploadrepo")

	r, err := NewRepository(repo, e, nil)
	if err != nil {
		return 0
	}

	noOfOps, err := fdp.GetInt()
	if err != nil {
		return 0
	}
	for i := 0; i < noOfOps%10; i++ {
		opType, err := fdp.GetInt()
		if err != nil {
			return 0
		}
		switch opType % 9 {
		case 0:
			tagServiceAll(r)
		case 1:
			tagServiceUntag(r, f)
		case 2:
			tagServiceGet(r, f)
		case 3:
			uploadBlob(r, f)
		case 4:
			getBlob(r, f)
		case 5:
			statBlob(r, f)
		case 6:
			manifestGet(r, f)
		case 7:
			manifestDelete(r, f)
		case 8:
			manifestPut(r, f)
		}
	}
	return 1
}

func tagServiceAll(r distribution.Repository) {
	tagService := r.Tags(context.Background())
	_, _ = tagService.All(context.Background())
}

func tagServiceUntag(r distribution.Repository, fdp *fuzz.ConsumeFuzzer) error {
	tagService := r.Tags(context.Background())
	tag, err := fdp.GetString()
	if err != nil {
		return err
	}
	_ = tagService.Untag(context.Background(), tag)
	return nil
}

func tagServiceGet(r distribution.Repository, fdp *fuzz.ConsumeFuzzer) error {
	tagService := r.Tags(context.Background())
	tag, err := fdp.GetString()
	if err != nil {
		return err
	}
	_, _ = tagService.Get(context.Background(), tag)
	return nil
}

func uploadBlob(r distribution.Repository, fdp *fuzz.ConsumeFuzzer) error {
	dgst, blob, err := newRandomBlobForFuzz(f)
	if err != nil {
		return err
	}

	l := r.Blobs(context.Background())

	upload, err := l.Create(context.Background())
	if err != nil {
		return nil
	}

	n, err := upload.ReadFrom(bytes.NewReader(blob))
	if err != nil {
		return nil
	}

	if n != int64(len(blob)) {
		panic(fmt.Sprintf("Unexpected ReadFrom length: %d; expected: %d\n", n, len(blob)))
	}

	_, _ = upload.Commit(context.Background(), distribution.Descriptor{
		Digest: dgst,
		Size:   int64(len(blob)),
	})

	return nil
}

func getBlob(r distribution.Repository, fdp *fuzz.ConsumeFuzzer) error {
	dgst, _, err := newRandomBlobForFuzz(f)
	if err != nil {
		return err
	}

	l := r.Blobs(context.Background())
	_, _ = l.Get(context.Background(), dgst)
	return nil
}

func statBlob(r distribution.Repository, fdp *fuzz.ConsumeFuzzer) error {
	dgst, _, err := newRandomBlobForFuzz(f)
	if err != nil {
		return err
	}

	l := r.Blobs(context.Background())
	_, _ = l.Stat(context.Background(), dgst)
	return nil
}

func manifestGet(r distribution.Repository, fdp *fuzz.ConsumeFuzzer) error {
	_, dgst, pl, err := newRandomOCIManifestForFuzz(f, fuzzRepo, "other")
	if err != nil {
		return err
	}
	var m testutil.RequestResponseMap
	addTestManifest(repo, dgst.String(), v1.MediaTypeImageManifest, pl, &m)
	ctx := context.Background()
	ms, err := r.Manifests(ctx)
	if err != nil {
		return err
	}
	_, _ = ms.Get(ctx, dgst)
	return nil
}

func manifestDelete(r distribution.Repository, fdp *fuzz.ConsumeFuzzer) error {
	_, dgst, _, err := newRandomOCIManifestForFuzz(f, fuzzRepo, "other")
	if err != nil {
		return err
	}
	ctx := context.Background()
	ms, err := r.Manifests(ctx)
	if err != nil {
		return err
	}
	_ = ms.Delete(ctx, dgst)
	return nil
}

func manifestPut(r distribution.Repository, fdp *fuzz.ConsumeFuzzer) error {
	ms, err := r.Manifests(context.Background())
	if err != nil {
		return nil
	}
	referenceName, err := fdp.GetString()
	if err != nil {
		return err
	}
	repo, _ := reference.WithName(referenceName)
	m1, _, _, err := newRandomOCIManifestForFuzz(f, repo, "other")
	if err != nil || m1 == nil {
		return nil
	}

	withTag, err := fdp.GetBool()
	if err != nil {
		return err
	}

	if withTag {
		if _, err := ms.Put(context.Background(), m1, distribution.WithTag(m1.Tag)); err != nil {
			return nil
		}
	} else {

		if _, err := ms.Put(context.Background(), m1); err != nil {
			return nil
		}
	}
	return nil
}
