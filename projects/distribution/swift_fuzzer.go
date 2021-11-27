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

package swift

import (
	"context"
	"io/ioutil"
	"os"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/ncw/swift"
	"github.com/ncw/swift/v2/swifttest"
)

const (
	TEST_ADDRESS = "localhost:5324"
	AUTH_URL     = "http://" + TEST_ADDRESS + "/v1.0"
	PROXY_URL    = "http://" + TEST_ADDRESS + "/proxy"
	USERNAME     = "test"
	APIKEY       = "apikey"
	AUTH_TOKEN   = "token"
	//defaultChunkSize = 20 * 1024 * 1024
)

var (
	srv *swifttest.SwiftServer
	con *swift.Connection
	err error
)

func startUp() error {
	srv, err = swifttest.NewSwiftServer("localhost")
	return err
}

func tearDown() {
	if srv != nil {
		srv.Close()
	}
}

func newSwiftDriver(root string) (*Driver, error) {
	parameters := Parameters{
		Username:    "swifttest",
		Password:    "swifttest",
		AuthURL:     srv.AuthURL,
		Region:      "",
		Tenant:      "",
		AuthVersion: 1,
		Container:   "c1",
	}
	return New(parameters)
}

func FuzzSwift(data []byte) int {
	f := fuzz.NewConsumer(data)
	putContent, err := f.GetBytes()
	if err != nil {
		return 0
	}
	writeContent, err := f.GetBytes()
	if err != nil {
		return 0
	}
	statPath, err := f.GetString()
	if err != nil {
		return 0
	}
	listPath, err := f.GetString()
	if err != nil {
		return 0
	}
	deletPath, err := f.GetString()
	if err != nil {
		return 0
	}
	urlforPath, err := f.GetString()
	if err != nil {
		return 0
	}

	err = startUp()
	if err != nil {
		return 0
	}
	defer tearDown()

	prefix, err := ioutil.TempDir("", "driver-")
	if err != nil {
		panic(err)
	}
	defer os.Remove(prefix)
	d, err := newSwiftDriver(prefix)
	if err != nil {
		panic(err)
	}

	err = d.PutContent(context.Background(), "/test", putContent)
	if err != nil {
		return 0
	}

	w, err := d.Writer(context.Background(), "/test", true)
	if err != nil {
		panic(err)
	}

	_, err = w.Write(writeContent)
	if err != nil {
		return 0
	}

	_, err = d.Stat(context.Background(), statPath)
	if err != nil {
		return 0
	}
	_, err = d.List(context.Background(), listPath)
	if err != nil {
		return 0
	}
	err = d.Delete(context.Background(), deletPath)
	if err != nil {
		return 0
	}
	_, err = d.URLFor(context.Background(), urlforPath, nil)
	if err != nil {
		return 0
	}

	return 1
}
