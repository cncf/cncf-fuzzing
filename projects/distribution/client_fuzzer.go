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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/docker/libtrust"
	"github.com/opencontainers/go-digest"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/manifest"
	"github.com/distribution/distribution/v3/manifest/schema1"
	"github.com/distribution/distribution/v3/reference"
	"github.com/distribution/distribution/v3/testutil"
)

func FuzzBlobServeBlob(data []byte) int {
	f := fuzz.NewConsumer(data)
	digestBytes, err := f.GetBytes()
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
	repo, _ := reference.WithName("test.example.com/repo1")
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

func FuzzClientPut(data []byte) int {
	f := fuzz.NewConsumer(data)
	repo, _ := reference.WithName("test.example.com/repo/delete")
	m1, dgst, _, err := newRandomSchemaV1ManifestForFuzz(f, repo, "other")
	if err != nil || m1 == nil {
		return 0
	}
	_, payload, err := m1.Payload()
	if err != nil {
		return 0
	}

	var m testutil.RequestResponseMap
	m = append(m, testutil.RequestResponseMapping{
		Request: testutil.Request{
			Method: "PUT",
			Route:  "/v2/" + repo.Name() + "/manifests/other",
			Body:   payload,
		},
		Response: testutil.Response{
			StatusCode: http.StatusAccepted,
			Headers: http.Header(map[string][]string{
				"Content-Length":        {"0"},
				"Docker-Content-Digest": {dgst.String()},
			}),
		},
	})

	putDgst := digest.FromBytes(m1.Canonical)
	m = append(m, testutil.RequestResponseMapping{
		Request: testutil.Request{
			Method: "PUT",
			Route:  "/v2/" + repo.Name() + "/manifests/" + putDgst.String(),
			Body:   payload,
		},
		Response: testutil.Response{
			StatusCode: http.StatusAccepted,
			Headers: http.Header(map[string][]string{
				"Content-Length":        {"0"},
				"Docker-Content-Digest": {putDgst.String()},
			}),
		},
	})

	e, tearDown := testServerForFuzz(m)
	defer tearDown()

	r, err := NewRepository(repo, e, nil)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	ms, err := r.Manifests(ctx)
	if err != nil {
		panic(err)
	}

	if _, err := ms.Put(ctx, m1, distribution.WithTag(m1.Tag)); err != nil {
		panic(err)
	}

	if _, err := ms.Put(ctx, m1); err != nil {
		panic(err)
	}
	return 1
}

func newRandomBlobForFuzz(f *fuzz.ConsumeFuzzer) (digest.Digest, []byte, error) {
	b, err := f.GetBytes()
	if err != nil {
		return digest.FromBytes([]byte("0")), nil, err
	}
	return digest.FromBytes(b), b, nil
}

func newRandomSchemaV1ManifestForFuzz(f *fuzz.ConsumeFuzzer, name reference.Named, tag string) (*schema1.SignedManifest, digest.Digest, []byte, error) {
	blobCount, err := f.GetInt()
	if err != nil {
		return nil, digest.FromBytes([]byte("0")), nil, err
	}
	if blobCount == 0 {
		return nil, digest.FromBytes([]byte("0")), nil, err
	}
	maxBlobCount := blobCount % 50
	if maxBlobCount == 0 {
		return nil, digest.FromBytes([]byte("0")), nil, err
	}
	blobs := make([]schema1.FSLayer, maxBlobCount)
	history := make([]schema1.History, maxBlobCount)

	for i := 0; i < maxBlobCount; i++ {
		dgst, blob, err := newRandomBlobForFuzz(f)
		if err != nil {
			return nil, digest.FromBytes([]byte("0")), nil, err
		}

		blobs[i] = schema1.FSLayer{BlobSum: dgst}
		history[i] = schema1.History{V1Compatibility: fmt.Sprintf("{\"Hex\": \"%x\"}", blob)}
	}

	m := schema1.Manifest{
		Name:         name.String(),
		Tag:          tag,
		Architecture: "x86",
		FSLayers:     blobs,
		History:      history,
		Versioned: manifest.Versioned{
			SchemaVersion: 1,
		},
	}

	pk, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		panic(err)
	}

	sm, err := schema1.Sign(&m, pk)
	if err != nil {
		panic(err)
	}

	return sm, digest.FromBytes(sm.Canonical), sm.Canonical, nil
}

func testServerForFuzz(rrm testutil.RequestResponseMap) (string, func()) {
	h := testutil.NewHandler(rrm)
	s := httptest.NewServer(h)
	return s.URL, s.Close
}
