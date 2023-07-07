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

package ratelimit

import (
	"net/http"
	"bytes"
	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	tollbooth "github.com/didip/tollbooth/v7"
	libstring "github.com/didip/tollbooth/v7/libstring"
	testhttp "github.com/stretchr/testify/http"
	"testing"
)

func FuzzRLTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r *http.Request
		var err error
		w := &testhttp.TestResponseWriter{}
		ff := fuzz.NewConsumer(data)

		body, err := ff.GetBytes()
		if err != nil {
			return
		}
		r, err = http.NewRequest(http.MethodGet, "localhost", bytes.NewReader(body))
		if err != nil {
			return
		}
		var noOfHeaders uint64
		noOfHeaders, err = ff.GetUint64()
		if err != nil {
			return
		}
		if noOfHeaders%100000 == 0 {
			noOfHeaders = 100
		}
		for i:=0; i<int(noOfHeaders)%100000;i++ {
			hKey, err := ff.GetString()
			if err != nil {
				return
			}
			if hKey == "" {
				continue
			}
			hValue, err := ff.GetString()
			if err != nil {
				return
			}
			if hValue == "" {
				continue
			}
			r.Header.Add(hKey, hValue)
		}
		
		if len(r.Header) < 2 {
			return
		}
		limiter := tollbooth.NewLimiter(4000000, nil)
		remoteIP := libstring.RemoteIP(limiter.GetIPLookups(), limiter.GetForwardedForIndexFromBehind(), r)
		remoteIP = libstring.CanonicalizeIP(remoteIP)
		if remoteIP == "" {
			r.Header.Set("X-Forwarded-For", "0.0.0.0")
		}
		httpError := tollbooth.LimitByRequest(limiter, w, r)
		if httpError != nil {
			limiter.ExecOnLimitReached(w, r)
		}
	})
}
