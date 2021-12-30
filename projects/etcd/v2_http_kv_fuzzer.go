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

package fuzzing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"go.etcd.io/etcd/tests/v3/framework/integration"

	"go.etcd.io/etcd/client/pkg/v3/transport"
)

var (
	u              string
	tc             *testHttpClient
	clusterInitter sync.Once
	cl             *integration.Cluster
)

func initCluster() {
	cl = integration.NewCluster(t, 1)
	cl.Launch(t)
	//defer cl.Terminate(t)

	u = cl.URL(0)
	tc = NewTestClient()
}

// This fuzzer currently sacrifices reproduceability
// for speed. For complete reproduceability a new cluster
// and a new client should be launched at each iteration,
// however the speed is so low, that it experimentally
// launches the cluster just once.
// execs/s when creating a cluster at each iteration: <40
// execs/s when creating a cluster only once: ~3,500
//
// The fuzzer is therefore experimental at the moment.
// The current objectives are:
// - to see if there will be ANY findings
//   in this part of the code base. If so, then the fuzzer will
//   be optimized for reproceability.
// - to generate a corpus that can be used later
func FuzzV2HTTP(data []byte) int {
	clusterInitter.Do(initCluster)
	f := fuzz.NewConsumer(data)
	randURL, err := f.GetString()
	if err != nil {
		return 0
	}
	bodyBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	body := bytes.NewReader(bodyBytes)

	var urlBuilder strings.Builder
	urlBuilder.WriteString(u)
	urlBuilder.WriteString(randURL)

	fullURL := urlBuilder.String()

	operationInt, err := f.GetInt()
	if err != nil {
		return 0
	}

	switch operationInt % 3 {
	case 0:
		_, _ = tc.Post(fullURL, "application/x-www-form-urlencoded", body)
	case 1:
		_, _ = tc.Put(fullURL, "application/x-www-form-urlencoded", body)
	case 2:
		_, _ = tc.Delete(fullURL, "application/x-www-form-urlencoded", body)
	}

	return 1
}

type testHttpClient struct {
	*http.Client
}

// Creates a new HTTP client with KeepAlive disabled.
func NewTestClient() *testHttpClient {
	tr, _ := transport.NewTransport(transport.TLSInfo{}, time.Second)
	tr.DisableKeepAlives = true
	return &testHttpClient{&http.Client{Transport: tr}}
}

// Reads the body from the response and closes it.
func (t *testHttpClient) ReadBody(resp *http.Response) []byte {
	if resp == nil {
		return []byte{}
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return body
}

// Reads the body from the response and parses it as JSON.
func (t *testHttpClient) ReadBodyJSON(resp *http.Response) map[string]interface{} {
	m := make(map[string]interface{})
	b := t.ReadBody(resp)
	if err := json.Unmarshal(b, &m); err != nil {
		panic(fmt.Sprintf("HTTP body JSON parse error: %v: %s", err, string(b)))
	}
	return m
}

func (t *testHttpClient) Head(url string) (*http.Response, error) {
	return t.send("HEAD", url, "application/json", nil)
}

func (t *testHttpClient) Get(url string) (*http.Response, error) {
	return t.send("GET", url, "application/json", nil)
}

func (t *testHttpClient) Post(url string, bodyType string, body io.Reader) (*http.Response, error) {
	return t.send("POST", url, bodyType, body)
}

func (t *testHttpClient) PostForm(url string, data url.Values) (*http.Response, error) {
	return t.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

func (t *testHttpClient) Put(url string, bodyType string, body io.Reader) (*http.Response, error) {
	return t.send("PUT", url, bodyType, body)
}

func (t *testHttpClient) PutForm(url string, data url.Values) (*http.Response, error) {
	return t.Put(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

func (t *testHttpClient) Delete(url string, bodyType string, body io.Reader) (*http.Response, error) {
	return t.send("DELETE", url, bodyType, body)
}

func (t *testHttpClient) DeleteForm(url string, data url.Values) (*http.Response, error) {
	return t.Delete(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

func (t *testHttpClient) send(method string, url string, bodyType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", bodyType)
	return t.Do(req)
}
