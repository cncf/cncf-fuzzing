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

var opsMap = map[int]string {
	0: "Name",
	1: "GetContent",
	2: "PutContent",
	3: "Reader",
	4: "Writer",
	5: "Stat",
	6: "List",
	7: "Move",
	8: "Delete",
	9: "URLFor",
}

func FuzzSwift(data []byte) int {
	f := fuzz.NewConsumer(data)

	noOfOps, err := f.GetInt()
	if err != nil {
		return 0
	}

	// Start swift test server
	err = startUp()
	if err != nil {
		return 0
	}
	defer tearDown()

	// Create switft driver
	prefix, err := ioutil.TempDir("", "driver-")
	if err != nil {
		return 0
	}
	defer os.Remove(prefix)
	d, err := newSwiftDriver(prefix)
	if err != nil {
		return 0
	}

	for i:=0;i<noOfOps%10;i++ {
		opType, err := f.GetInt()
		if err != nil {
			return 0
		}
		switch opsMap[opType%len(opsMap)] {
		case "Name":
			_ = d.Name()
		case "GetContent":
			path, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = d.GetContent(context.Background(), path)
		case "PutContent":
			path, err := f.GetString()
			if err != nil {
				return 0
			}
			contents, err := f.GetBytes()
			if err != nil {
				return 0
			}
			err = d.PutContent(context.Background(), path, contents)
			if err == nil {
				received, err := d.GetContent(context.Background(), path)
				if err != nil {
					panic("err should not be nil")
				}
				if len(received) != len(contents) {
					panic("these should be identical")
				}
			}
		case "Reader":
			path, err := f.GetString()
			if err != nil {
				return 0
			}
			offset, err := f.GetInt()
			if err != nil {
				return 0
			}
			_, _ = d.Reader(context.Background(), path, int64(offset))
		case "Writer":
			path, err := f.GetString()
			if err != nil {
				return 0
			}
			append, err := f.GetBool()
			if err != nil {
				return 0
			}
			contents, err := f.GetBytes()
			if err != nil {
				return 0
			}
			fileWriter, err := d.Writer(context.Background(), path, append)
			if err == nil {
				defer fileWriter.Close()
				defer d.Delete(context.Background(), path)
				_, err2 := fileWriter.Write(contents)
				if err2 == nil {
					fileWriter.Commit()
					if fileWriter.Size() != int64(len(contents)) {
						panic("len is not identical")
					}
					readContents, err := d.GetContent(context.Background(), path)
					if err != nil {
						panic("panicked when reading contents we just wrote")
					}
					if len(readContents) != len(contents) {
						panic("len of contents we wrote is not identical to len of read contents")
					}
				}
			}
		case "Stat":
			path, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = d.Stat(context.Background(), path)
		case "List":
			path, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = d.Stat(context.Background(), path)
		case "Move":
			sourcePath, err := f.GetString()
			if err != nil {
				return 0
			}
			destPath, err := f.GetString()
			if err != nil {
				return 0
			}
			d.Move(context.Background(), sourcePath, destPath)
		case "Delete":
			path, err := f.GetString()
			if err != nil {
				return 0
			}
			d.Delete(context.Background(), path)
		case "URLFor":
			path, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = d.URLFor(context.Background(), path, nil)
		}
	}

	return 1
}
