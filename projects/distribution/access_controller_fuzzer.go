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

package htpasswd

import (
	"fmt"
	"github.com/distribution/distribution/v3/context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/distribution/distribution/v3/registry/auth"
)

func FuzzAccessController(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)
		testHtpasswdContent, err := fdp.GetString()
		if err != nil {
			return
		}
		testRealm, err := fdp.GetString()
		if err != nil {
			return
		}
		testUser, err := fdp.GetString()
		if err != nil {
			return
		}
		testPassword, err := fdp.GetString()
		if err != nil {
			return
		}

		tempFile, err := ioutil.TempFile("", "htpasswd-test")
		if err != nil {
			return
		}
		if _, err = tempFile.WriteString(testHtpasswdContent); err != nil {
			return
		}

		options := map[string]interface{}{
			"realm": testRealm,
			"path":  tempFile.Name(),
		}
		ctx := context.Background()

		accessController, err := newAccessController(options)
		if err != nil {
			return
		}

		tempFile.Close()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithRequest(ctx, r)
			authCtx, err := accessController.Authorized(ctx)
			if err != nil {
				switch err := err.(type) {
				case auth.Challenge:
					err.SetHeaders(r, w)
					w.WriteHeader(http.StatusUnauthorized)
					return
				default:
					return
				}
			}

			userInfo, ok := authCtx.Value(auth.UserKey).(auth.UserInfo)
			if !ok {
				return
			}

			if userInfo.Name != testUser {
				return
			}

			w.WriteHeader(http.StatusNoContent)
		}))
		server.URL = "http://127.0.0.1:1000"

		defer server.Close()

		client := &http.Client{
			CheckRedirect: nil,
		}

		req, _ := http.NewRequest("GET", server.URL, nil)
		resp, err := client.Do(req)

		if err != nil {
			return
		}
		defer resp.Body.Close()

		// Request should not be authorized
		if resp.StatusCode != http.StatusUnauthorized {
			panic(fmt.Sprintf("unexpected non-fail response status: %v != %v\n", resp.StatusCode, http.StatusUnauthorized))
		}

		req, err = http.NewRequest("GET", server.URL, nil)
		if err != nil {
			return
		}

		req.SetBasicAuth(testUser, testPassword)

		resp, err = client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
	})
}
