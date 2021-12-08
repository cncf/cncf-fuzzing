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

package server

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/httpstream/spdy"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func init() {
	testing.Init()
}

func errorHandler() {
	if r := recover(); r != nil {
		fmt.Println(r)
	}
}

func FuzzRequest(data []byte) int {
	defer errorHandler()
	t := &testing.T{}
	f := fuzz.NewConsumer(data)
	urlString, err := f.GetString()
	if err != nil {
		return 0
	}
	ss, err := newTestStreamingServer(100 * time.Millisecond)
	if err != nil {
		return 0
	}
	defer ss.testHTTPServer.Close()
	fw := newServerTestWithDebug(true, ss)
	defer fw.testHTTPServer.Close()

	url := fw.testHTTPServer.URL + urlString

	upgradeRoundTripper := spdy.NewRoundTripper(nil, true, true)
	c := &http.Client{Transport: upgradeRoundTripper}

	resp, err := c.Do(makeReq(t, "POST", url, "v4.channel.k8s.io"))
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return 1
}
