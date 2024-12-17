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

package filesystem

import (
	"context"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"os"
	"testing"
)

func FuzzFilesystemDriver(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)
		err := os.Mkdir("fuzz-dir", 0755)
		if err != nil {
			return
		}
		defer os.RemoveAll("fuzz-dir")
		params := map[string]interface{}{
			"maxthreads":    1,
			"rootdirectory": "fuzz-dir",
		}
		driver, err := FromParameters(params)
		if err != nil {
			return
		}

		noOfOps, err := fdp.GetInt()
		if err != nil {
			return
		}
		for i := 0; i < noOfOps%10; i++ {
			opType, err := fdp.GetInt()
			if err != nil {
				return
			}
			switch opType % 10 {
			case 0:
				err := fdp.CreateFiles("fuzz-dir")
				if err != nil {
					return
				}
			case 1:
				path, err := fdp.GetString()
				if err != nil {
					return
				}
				_, _ = driver.GetContent(context.Background(), path)
			case 2:
				subPath, err := fdp.GetString()
				if err != nil {
					return
				}
				contents, err := fdp.GetBytes()
				if err != nil {
					return
				}
				_ = driver.PutContent(context.Background(), subPath, contents)
			case 3:
				path, err := fdp.GetString()
				if err != nil {
					return
				}
				offset, err := fdp.GetInt()
				if err != nil {
					return
				}
				reader, err := driver.Reader(context.Background(), path, int64(offset))
				if err == nil {
					defer reader.Close()
				}
			case 4:
				subPath, err := fdp.GetString()
				if err != nil {
					return
				}
				fi, err := driver.Stat(context.Background(), subPath)
				if err == nil {
					_ = fi.Path()
					_ = fi.Size()
					_ = fi.ModTime()
				}
			case 5:
				subPath, err := fdp.GetString()
				if err != nil {
					return
				}
				_, _ = driver.List(context.Background(), subPath)
			case 6:
				sourcePath, err := fdp.GetString()
				if err != nil {
					return
				}
				destPath, err := fdp.GetString()
				if err != nil {
					return
				}
				_ = driver.Move(context.Background(), sourcePath, destPath)
			case 7:
				subPath, err := fdp.GetString()
				if err != nil {
					return
				}
				_ = driver.Delete(context.Background(), subPath)
			case 8:
				path, err := fdp.GetString()
				if err != nil {
					return
				}
				err = driver.Walk(context.Background(), path, func(fileInfo storagedriver.FileInfo) error {
					return nil
				})
			case 9:
				subPath, err := fdp.GetString()
				if err != nil {
					return
				}
				append, err := fdp.GetBool()
				if err != nil {
					return
				}
				fw, err := driver.Writer(context.Background(), subPath, append)
				if err != nil {
					return
				}
				defer fw.Close()
				p, err := fdp.GetBytes()
				if err != nil {
					return
				}
				_, err = fw.Write(p)
				if err != nil {
					return
				}
				_ = fw.Commit(context.Background())
			}
		}
	})
}
