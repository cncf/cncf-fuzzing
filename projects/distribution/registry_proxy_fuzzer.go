// Copyright 2022 ADA Logics Ltd
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

package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/docker/libtrust"
	"github.com/opencontainers/go-digest"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest"
	"github.com/distribution/distribution/v3/manifest/schema1"
	"github.com/distribution/distribution/v3/registry/proxy/scheduler"
	"github.com/distribution/distribution/v3/registry/storage"
	"github.com/distribution/distribution/v3/registry/storage/cache/memory"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/reference"
)

func FuzzProxyBlobstore(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		t := &testing.T{}
		te := makeTestEnv(t, "foo/bar")
		fdp := fuzz.NewConsumer(data)
		err := populateForFuzzing(te, f)
		if err != nil {
			return
		}
		noOfOps, err := fdp.GetInt()
		if err != nil {
			return
		}
		for i := 0; i < noOfOps%10; i++ {
			opType, err := fdp.GetInt()
			if err != nil {
				return
			}
			switch opType % 3 {
			case 0:
				// Get
				if len(te.inRemote) > 0 {
					for i := 0; i < len(te.inRemote); i++ {
						_, _ = te.store.Get(context.Background(), te.inRemote[i].Digest)
					}
				}
			case 1:
				if len(te.inRemote) > 0 {
					for _, d := range te.inRemote {
						_, _ = te.store.Stat(context.Background(), d.Digest)
					}
				}
			case 2:
				for _, dr := range te.inRemote {
					w := httptest.NewRecorder()
					r, err := http.NewRequest("GET", "", nil)
					if err != nil {
						return
					}

					err = te.store.ServeBlob(context.Background(), w, r, dr.Digest)
					if err != nil {
						return
					}

					dl := digest.FromBytes(w.Body.Bytes())
					if dl != dr.Digest {
						panic("Mismatching blob fetch from proxy")
					}
				}
			}
		}
	})
}
func populateForFuzzing(te *testEnv, fdp *fuzz.ConsumeFuzzer) error {
	var inRemote []distribution.Descriptor

	numUnique, err := fdp.GetInt()
	if err != nil {
		return err
	}
	blobCount, err := fdp.GetInt()
	if err != nil {
		return err
	}

	for i := 0; i < numUnique%30; i++ {
		blobBytes, err := fdp.GetBytes()
		if err != nil {
			return err
		}
		for j := 0; j < blobCount/numUnique; j++ {
			desc, err := te.store.remoteStore.Put(context.Background(), "", blobBytes)
			if err != nil {
				return err
			}

			inRemote = append(inRemote, desc)
		}
	}

	te.inRemote = inRemote
	te.numUnique = numUnique
	return nil
}

func FuzzProxyManifestStore(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		name := "foo/bar"
		f := fuzz.NewConsumer(data)
		env, err := newManifestStoreTestEnvFuzz(f, name, "latest")
		if err != nil {
			return 0
		}
		dBytes, err := f.GetBytes()
		if err != nil {
			return 0
		}
		d1 := digest.FromBytes(dBytes)
		_, _ = env.manifests.Exists(context.Background(), d1)
		_, _ = env.manifests.Get(context.Background(), d1)
		return 1
	})
}

func newManifestStoreTestEnvFuzz(f *fuzz.ConsumeFuzzer, name, tag string) (*manifestStoreTestEnv, error) {
	nameRef, err := reference.WithName(name)
	if err != nil {
		return nil, err
	}
	k, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	truthRegistry, err := storage.NewRegistry(ctx, inmemory.New(),
		storage.BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider(memory.UnlimitedSize)),
		storage.Schema1SigningKey(k),
		storage.EnableSchema1)
	if err != nil {
		return nil, err
	}
	truthRepo, err := truthRegistry.Repository(ctx, nameRef)
	if err != nil {
		return nil, err
	}
	tr, err := truthRepo.Manifests(ctx)
	if err != nil {
		return nil, err
	}
	truthManifests := statsManifest{
		manifests: tr,
		stats:     make(map[string]int),
	}

	manifestDigest, err := populateRepoFuzz(ctx, f, truthRepo, name, tag)
	if err != nil {
		return nil, err
	}

	localRegistry, err := storage.NewRegistry(ctx, inmemory.New(), storage.BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider(memory.UnlimitedSize)), storage.EnableRedirect, storage.DisableDigestResumption, storage.Schema1SigningKey(k), storage.EnableSchema1)
	if err != nil {
		return nil, err
	}
	localRepo, err := localRegistry.Repository(ctx, nameRef)
	if err != nil {
		return nil, err
	}
	lr, err := localRepo.Manifests(ctx)
	if err != nil {
		return nil, err
	}

	localManifests := statsManifest{
		manifests: lr,
		stats:     make(map[string]int),
	}

	s := scheduler.New(ctx, inmemory.New(), "/scheduler-state.json")
	return &manifestStoreTestEnv{
		manifestDigest: manifestDigest,
		manifests: proxyManifestStore{
			ctx:             ctx,
			localManifests:  localManifests,
			remoteManifests: truthManifests,
			scheduler:       s,
			repositoryName:  nameRef,
			authChallenger:  &mockChallenger{},
		},
	}, nil
}

func populateRepoFuzz(ctx context.Context, f *fuzz.ConsumeFuzzer, repository distribution.Repository, name, tag string) (digest.Digest, error) {
	m := schema1.Manifest{
		Versioned: manifest.Versioned{
			SchemaVersion: 1,
		},
		Name: name,
		Tag:  tag,
	}

	for i := 0; i < 2; i++ {
		wr, err := repository.Blobs(ctx).Create(ctx)
		if err != nil {
			return digest.FromString("0"), err
		}

		rs, err := f.TarBytes()
		if err != nil {
			return digest.FromString("0"), err
		}
		if _, err := io.Copy(wr, bytes.NewReader(rs)); err != nil {
			return digest.FromString("0"), err
		}
		dgst := digest.FromBytes(rs)

		if _, err := wr.Commit(ctx, distribution.Descriptor{Digest: dgst}); err != nil {
			return digest.FromString("0"), err
		}
	}

	pk, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		return digest.FromString("0"), err
	}

	sm, err := schema1.Sign(&m, pk)
	if err != nil {
		return digest.FromString("0"), err
	}

	ms, err := repository.Manifests(ctx)
	if err != nil {
		return digest.FromString("0"), err
	}
	dgst, err := ms.Put(ctx, sm)
	if err != nil {
		return digest.FromString("0"), err
	}

	return dgst, nil
}
