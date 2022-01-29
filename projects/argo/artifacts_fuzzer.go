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

package artifacts

import (
	testhttp "github.com/stretchr/testify/http"
	"net/http"
	"net/url"
	"strings"
)

func mustParseFuzz(text string) (*url.URL, error) {
	u, err := url.Parse(text)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func FuzzGetOutputArtifact(data []byte) int {
	var url strings.Builder
	url.WriteString("/")
	url.WriteString(string(data))
	s := newServer()
	r := &http.Request{}
	parsedUrl, err := mustParseFuzz(url.String())
	if err != nil {
		return 0
	}
	r.URL = parsedUrl
	w := &testhttp.TestResponseWriter{}
	s.GetOutputArtifact(w, r)
	return 0
}

func FuzzGetOutputArtifactByUID(data []byte) int {
	var url strings.Builder
	url.WriteString("/")
	url.WriteString(string(data))
	s := newServer()
	r := &http.Request{}
	parsedUrl, err := mustParseFuzz(url.String())
	if err != nil {
		return 0
	}
	r.URL = parsedUrl
	w := &testhttp.TestResponseWriter{}
	s.GetInputArtifactByUID(w, r)
	s.GetOutputArtifactByUID(w, r)
	return 0
}
