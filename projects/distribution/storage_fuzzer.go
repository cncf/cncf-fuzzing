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

package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest/schema2"
	"github.com/distribution/distribution/v3/reference"
	"github.com/distribution/distribution/v3/registry/storage/cache/memory"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/distribution/v3/testutil"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func init() {
	testing.Init()
}

func FuzzFR(data []byte) int {
	dir, err := ioutil.TempDir(".", "test-dir-")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(dir)
	driver := inmemory.New()
	fr, err := newFileReader(context.Background(), driver, dir, 10)
	if err != nil {
		return 0
	}
	_, _ = fr.Read(data)
	return 0
}

// CreateRandomTarFile creates a random tarfile, returning it as an
// io.ReadSeeker along with its digest. An error is returned if there is a
// problem generating valid content.
func CreateRandomTarFile(f *fuzz.ConsumeFuzzer) (rs io.ReadSeeker, dgst digest.Digest, err error) {
	nF, err := f.GetInt()
	if err != nil {
		return nil, "", err
	}
	nFiles := nF % 1000
	target := &bytes.Buffer{}
	wr := tar.NewWriter(target)

	header := &tar.Header{
		Mode:       0644,
		ModTime:    time.Now(),
		Typeflag:   tar.TypeReg,
		Uname:      "randocalrissian",
		Gname:      "cloudcity",
		AccessTime: time.Now(),
		ChangeTime: time.Now(),
	}

	for fileNumber := 0; fileNumber < nFiles; fileNumber++ {
		fSize, err := f.GetInt()
		if err != nil {
			return nil, "", err
		}
		fileSize := fSize % 1000

		header.Name = fmt.Sprint(fileNumber)
		header.Size = int64(fileSize)

		if err := wr.WriteHeader(header); err != nil {
			return nil, "", err
		}
		randomData, err := f.GetBytes()
		if err != nil {
			return nil, "", err
		}

		nn, err := io.Copy(wr, bytes.NewReader(randomData))
		if nn != int64(fileSize) {
			return nil, "", fmt.Errorf("short copy writing random file to tar")
		}

		if err != nil {
			return nil, "", err
		}

		if err := wr.Flush(); err != nil {
			return nil, "", err
		}
	}

	if err := wr.Close(); err != nil {
		return nil, "", err
	}

	dgst = digest.FromBytes(target.Bytes())

	return bytes.NewReader(target.Bytes()), dgst, nil
}

// seekerSizeFuzz seeks to the end of seeker, checks the size and returns it to
// the original state, returning the size. The state of the seeker should be
// treated as unknown if an error is returned.
func seekerSizeFuzz(seeker io.ReadSeeker) (int64, error) {
	current, err := seeker.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}

	end, err := seeker.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}

	resumed, err := seeker.Seek(current, io.SeekStart)
	if err != nil {
		return 0, err
	}

	if resumed != current {
		return 0, fmt.Errorf("error returning seeker to original state, could not seek back to original location")
	}

	return end, nil
}

func FuzzBlob(data []byte) int {
	f := fuzz.NewConsumer(data)
	randomDataReader, dgst, err := CreateRandomTarFile(f)
	if err != nil {
		return 0
	}
	ctx := context.Background()
	imageName, _ := reference.WithName("foo/bar")
	driver := inmemory.New()
	registry, err := NewRegistry(ctx, driver, BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider(memory.UnlimitedSize)), EnableDelete, EnableRedirect)
	if err != nil {
		return 0
	}
	repository, err := registry.Repository(ctx, imageName)
	if err != nil {
		return 0
	}
	bs := repository.Blobs(ctx)

	h := sha256.New()
	rd := io.TeeReader(randomDataReader, h)

	blobUpload, err := bs.Create(ctx)
	if err != nil {
		return 0
	}

	// Get the size of our random tarfile
	randomDataSize, err := seekerSizeFuzz(randomDataReader)
	if err != nil {
		return 0
	}

	nn, err := io.Copy(blobUpload, rd)
	if err != nil {
		return 0
	}

	if nn != randomDataSize {
		panic(fmt.Sprintf(("layer data write incomplete")))
	}

	blobUpload.Close()

	offset := blobUpload.Size()
	if offset != nn {
		return 0
	}

	// Do a resume, for good fun
	blobUpload, err = bs.Resume(ctx, blobUpload.ID())
	if err != nil {
		return 0
	}

	_, err = blobUpload.Commit(ctx, distribution.Descriptor{Digest: dgst})
	if err != nil {
		return 0
	}
	return 1
}

func FuzzSchema2ManifestHandler(data []byte) int {
	t := &testing.T{}
	f := fuzz.NewConsumer(data)
	m := schema2.Manifest{}
	err := f.GenerateStruct(&m)
	if err != nil {
		return 0
	}
	dm, err := schema2.FromStruct(m)
	if err != nil {
		fmt.Println(err)
		return 0
	}

	ctx := context.Background()
	_ = ctx
	inmemoryDriver := inmemory.New()
	registry := createRegistry(t, inmemoryDriver,
		ManifestURLsAllowRegexp(regexp.MustCompile("^https?://foo")),
		ManifestURLsDenyRegexp(regexp.MustCompile("^https?://foo/nope")))
	repo := makeRepository(t, registry, "test")
	manifestService := makeManifestService(t, repo)
	_ = manifestService
	_, err = manifestService.Put(ctx, dm)
	if err != nil {

	}
	return 1
}

// CreateRandomLayers returns a map of n digests. We don't particularly care
// about the order of said digests (since they're all random anyway).
func CreateRandomLayersFuzz(n int, f *fuzz.ConsumeFuzzer) (map[digest.Digest]io.ReadSeeker, error) {
	digestMap := map[digest.Digest]io.ReadSeeker{}
	for i := 0; i < n; i++ {
		rs, ds, err := CreateRandomTarFile(f)
		if err != nil {
			return nil, fmt.Errorf("unexpected error generating test layer file: %v", err)
		}

		digestMap[ds] = rs
	}
	return digestMap, nil
}

func FuzzMarkAndSweep(data []byte) int {
	f := fuzz.NewConsumer(data)

	// Create random layers
	randomLayers1, err := CreateRandomLayersFuzz(3, f)
	if err != nil {
		return 0
	}

	randomLayers2, err := CreateRandomLayersFuzz(3, f)
	if err != nil {
		return 0
	}

	t := &testing.T{}
	ctx := context.Background()
	inmemoryDriver := inmemory.New()

	registry := createRegistry(t, inmemoryDriver)
	repo := makeRepository(t, registry, "deletemanifests")
	manifestService, _ := repo.Manifests(ctx)

	// Upload all layers
	err = testutil.UploadBlobs(repo, randomLayers1)
	if err != nil {
		return 0
	}

	err = testutil.UploadBlobs(repo, randomLayers2)
	if err != nil {
		return 0
	}

	// Construct manifests
	manifest1, err := testutil.MakeSchema1Manifest(getKeys(randomLayers1))
	if err != nil {
		return 0
	}

	manifest2, err := testutil.MakeSchema1Manifest(getKeys(randomLayers2))
	if err != nil {
		return 0
	}

	_, err = manifestService.Put(ctx, manifest1)
	if err != nil {
		return 0
	}

	_, err = manifestService.Put(ctx, manifest2)
	if err != nil {
		return 0
	}

	manifestEnumerator, _ := manifestService.(distribution.ManifestEnumerator)
	manifestEnumerator.Enumerate(ctx, func(dgst digest.Digest) error {
		repo.Tags(ctx).Tag(ctx, "test", distribution.Descriptor{Digest: dgst})
		return nil
	})

	before1 := allBlobs(t, registry)
	before2 := allManifests(t, manifestService)

	// run GC with dry-run (should not remove anything)
	err = MarkAndSweep(context.Background(), inmemoryDriver, registry, GCOpts{
		DryRun:         true,
		RemoveUntagged: true,
	})
	if err != nil {
		panic(err)
	}
	afterDry1 := allBlobs(t, registry)
	afterDry2 := allManifests(t, manifestService)
	if len(before1) != len(afterDry1) {
		panic(fmt.Sprintf("Garbage collection affected blobs storage: %d != %d\n", len(before1), len(afterDry1)))
	}
	if len(before2) != len(afterDry2) {
		panic(fmt.Sprintf("Garbage collection affected manifest storage: %d != %d", len(before2), len(afterDry2)))
	}

	// Run GC (removes everything because no manifests with tags exist)
	_ = MarkAndSweep(context.Background(), inmemoryDriver, registry, GCOpts{
		DryRun:         false,
		RemoveUntagged: true,
	})

	return 1
}
