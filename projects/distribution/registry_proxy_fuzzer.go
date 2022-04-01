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
	"context"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/distribution/distribution/v3"
	"github.com/opencontainers/go-digest"
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzProxyBlobstore(data []byte) int {
	t := &testing.T{}
	te := makeTestEnv(t, "foo/bar")
	f := fuzz.NewConsumer(data)
	err := populateForFuzzing(te, f)
	if err != nil {
		return 0
	}
	noOfOps, err := f.GetInt()
	if err != nil {
		return 0
	}
	for i := 0; i < noOfOps%10; i++ {
		opType, err := f.GetInt()
		if err != nil {
			return 0
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
					return 0
				}

				err = te.store.ServeBlob(context.Background(), w, r, dr.Digest)
				if err != nil {
					return 0
				}

				dl := digest.FromBytes(w.Body.Bytes())
				if dl != dr.Digest {
					panic("Mismatching blob fetch from proxy")
				}
			}
		}
	}
	return 1
}

func populateForFuzzing(te *testEnv, f *fuzz.ConsumeFuzzer) error {
	var inRemote []distribution.Descriptor

	numUnique, err := f.GetInt()
	if err != nil {
		return err
	}
	blobCount, err := f.GetInt()
	if err != nil {
		return err
	}

	for i := 0; i < numUnique%30; i++ {
		blobBytes, err := f.GetBytes()
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
