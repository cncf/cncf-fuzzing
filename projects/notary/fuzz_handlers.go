// Copyright 2023 the cncf-fuzzing authors
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

package handlers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	ctxu "github.com/docker/distribution/context"
	"github.com/sirupsen/logrus"

	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/server/storage"
	store "github.com/theupdateframework/notary/storage"
	"github.com/theupdateframework/notary/tuf"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/signed"
	"github.com/theupdateframework/notary/tuf/testutils"
)

func getFuzzContext(h handlerStateFuzz) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, notary.CtxKeyMetaStore, h.store)
	ctx = context.WithValue(ctx, notary.CtxKeyKeyAlgo, h.keyAlgo)
	ctx = context.WithValue(ctx, notary.CtxKeyCryptoSvc, h.crypto)
	return ctxu.WithLogger(ctx, ctxu.GetRequestLogger(ctx))
}

type handlerStateFuzz struct {
	store   interface{}
	crypto  interface{}
	keyAlgo interface{}
}

type MockWriter struct {
}

func (m MockWriter) Header() http.Header {
	return http.Header{}
}

func (m MockWriter) Write(data []byte) (int, error) {
	return 0, nil
}

func (m MockWriter) WriteHeader(statusCode int) {
}

func mustCopyKeysFuzz(from signed.CryptoService, roles ...data.RoleName) (signed.CryptoService, error) {
	return testutils.CopyKeys(from, roles...)
}

var (
	metaStore  *storage.MemStorage
	vars       map[string]string
	repo       *tuf.Repo
	cs, crypto signed.CryptoService
)

func init() {
	metaStore = storage.NewMemStorage()

	var gun data.GUN = "testGUN"
	vars := make(map[string]string)
	vars["gun"] = gun.String()

	_, cs, err := testutils.EmptyRepo(gun)
	if err != nil {
		panic(err)
	}

	crypto, err = mustCopyKeysFuzz(cs, data.CanonicalTimestampRole)
	if err != nil {
		panic(err)
	}

	logrus.SetLevel(logrus.PanicLevel)
}

func FuzzAtomicUpdateHandler(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, headerData []byte) {
		ff := fuzz.NewConsumer(headerData)

		r, err := http.NewRequest("POST", "", bytes.NewReader(body))
		if err != nil {
			t.Skip()
		}
		noOfHeaders, err := ff.GetInt()
		if err != nil {
			t.Skip()
		}
		for i := 0; i < noOfHeaders%5; i++ {
			key, err := ff.GetString()
			if err != nil {
				t.Skip()
			}
			value, err := ff.GetString()
			if err != nil {
				t.Skip()
			}
			r.Header.Add(key, value)
		}
		boundary, err := ff.GetString()
		if err != nil {
			t.Skip()
		}

		var mp strings.Builder
		mp.WriteString("multipart/form-data; boundary=")
		mp.WriteString(boundary)
		r.Header.Add("Content-Type", mp.String())

		state := handlerStateFuzz{store: metaStore, crypto: crypto}
		AtomicUpdateHandler(getFuzzContext(state), MockWriter{}, r)
	})
}

func FuzzAtomicUpdateHandlerMultipart(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, headerData []byte) {
		ff := fuzz.NewConsumer(headerData)

		metas := make(map[string][]byte)
		ff.FuzzMap(&metas)

		r, err := store.NewMultiPartMetaRequest("", metas)
		if err != nil {
			t.Skip()
		}
		reader, err := r.MultipartReader()
		if err != nil {
			t.Skip()
		}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if part == nil {
				t.Skip()
			}
			if part.Header == nil {
				t.Skip()
			}
		}

		state := handlerStateFuzz{store: metaStore, crypto: crypto}
		AtomicUpdateHandler(getFuzzContext(state), MockWriter{}, r)
	})
}



func FuzzGetKeyHandler(f *testing.F) {
	f.Fuzz(func(t *testing.T, body, headerData []byte) {
		ff := fuzz.NewConsumer(headerData)

		r, err := http.NewRequest("POST", "", bytes.NewReader(body))
		if err != nil {
			t.Skip()
		}
		noOfHeaders, err := ff.GetInt()
		if err != nil {
			t.Skip()
		}
		for i := 0; i < noOfHeaders%5; i++ {
			key, err := ff.GetString()
			if err != nil {
				t.Skip()
			}
			value, err := ff.GetString()
			if err != nil {
				t.Skip()
			}
			r.Header.Add(key, value)
		}
		boundary, err := ff.GetString()
		if err != nil {
			t.Skip()
		}

		var mp strings.Builder
		mp.WriteString("multipart/form-data; boundary=")
		mp.WriteString(boundary)
		r.Header.Add("Content-Type", mp.String())

		state := handlerStateFuzz{store: metaStore, crypto: crypto}
		GetKeyHandler(getFuzzContext(state), MockWriter{}, r)
	})
}
