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

package s3

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/awstesting/unit"
	"github.com/aws/aws-sdk-go/service/s3"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/base"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

var (
	availablePaths []string
)

func newS3DriverForFuzzing(rootDir string) *Driver {
	sess := unit.Session
	s3obj := s3.New(sess)
	d := &driver{
		S3:                          s3obj,
		RootDirectory:               rootDir,
		Bucket:                      "mock-bucket",
		MultipartCopyChunkSize:      int64(defaultMultipartCopyChunkSize),
		MultipartCopyMaxConcurrency: int64(defaultMultipartCopyMaxConcurrency),
		MultipartCopyThresholdSize:  int64(defaultMultipartCopyThresholdSize),
	}

	return &Driver{
		baseEmbed: baseEmbed{
			Base: base.Base{
				StorageDriver: d,
			},
		},
	}
}

func FuzzS3Driver(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		availablePaths = make([]string, 0)
		fdp := fuzz.NewConsumer(data)

		backend := s3mem.New()
		faker := gofakes3.New(backend)
		ts := httptest.NewServer(faker.Server())
		defer ts.Close()

		s3Config := &aws.Config{
			Credentials:      credentials.NewStaticCredentials("YOUR-ACCESSKEYID", "YOUR-SECRETACCESSKEY", ""),
			Endpoint:         aws.String(ts.URL),
			Region:           aws.String("eu-central-1"),
			DisableSSL:       aws.Bool(true),
			S3ForcePathStyle: aws.Bool(true),
		}
		newSession := session.New(s3Config)

		s3Client := s3.New(newSession)
		cparams := &s3.CreateBucketInput{
			Bucket: aws.String("newbucket"),
		}

		// Create a new bucket using the CreateBucket call.
		_, err := s3Client.CreateBucket(cparams)
		if err != nil {
			return
		}
		dr := &driver{
			S3:                          s3Client,
			Bucket:                      "newbucket",
			MultipartCopyChunkSize:      int64(defaultMultipartCopyChunkSize),
			MultipartCopyMaxConcurrency: int64(defaultMultipartCopyMaxConcurrency),
			MultipartCopyThresholdSize:  int64(defaultMultipartCopyThresholdSize),
		}

		d := &Driver{
			baseEmbed: baseEmbed{
				Base: base.Base{
					StorageDriver: dr,
				},
			},
		}

		err = doRandomOperationts(d, fdp)
		if err != nil {
			return
		}
	})
}

func doRandomOperationts(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	noOfOperations, err := fdp.GetInt()
	if err != nil {
		return err
	}
	maxOperations := noOfOperations % 100
	noOfOps := 8
	for i := 0; i < maxOperations; i++ {
		op, err := fdp.GetInt()
		if err != nil {
			return err
		}
		if op%noOfOps == 0 {
			err = putContentFuzz(d, fdp)
			if err != nil {
				return err
			}
		} else if op%noOfOps == 1 {
			err = doWalkFuzz(d, fdp)
			if err != nil {
				return err
			}
		} else if op%noOfOps == 2 {
			err = doWriteFuzz(d, fdp)
			if err != nil {
				return err
			}
		} else if op%noOfOps == 3 {
			err = doStatFuzz(d, fdp)
			if err != nil {
				return err
			}
		} else if op%noOfOps == 4 {
			err = doMoveFuzz(d, fdp)
			if err != nil {
				return err
			}
		} else if op%noOfOps == 5 {
			err = doDeleteFuzz(d, fdp)
			if err != nil {
				return err
			}
		} else if op%noOfOps == 6 {
			err = doListFuzz(d, fdp)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func putContentFuzz(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	putContent, err := fdp.GetBytes()
	if err != nil {
		return err
	}
	pathLength, err := fdp.GetInt()
	if err != nil {
		return err
	}
	if pathLength%100 == 0 {
		return errors.New("Too short path")
	}
	path, err := fdp.GetStringFrom("abcdefghijklmnopqrstuvwxyz123456789-.", pathLength%100)
	if err != nil {
		return err
	}
	path = fmt.Sprintf("/%s", path)
	err = d.PutContent(context.Background(), path, putContent)
	if err != nil {
		return err
	}
	availablePaths = append(availablePaths, path)
	return nil
}

func doWalkFuzz(d *Driver, f *fuzz.ConsumeFuzzer) error {
	path, err := getAvailablePath(f)
	if err != nil {
		return err
	}
	d.Walk(context.Background(), path, func(fileInfo storagedriver.FileInfo) error {
		return nil
	})
	return nil
}

func doWriteFuzz(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	writeContent, err := fdp.GetBytes()
	if err != nil {
		return err
	}
	if len(writeContent) < 3 {
		return err
	}
	path, err := getAvailablePath(fdp)
	if err != nil {
		return err
	}

	w, err := d.Writer(context.Background(), path, true)
	if err != nil {
		return err
	}
	go func() {
		_, err = w.Write(writeContent)
		if err != nil {
		}
	}()
	return nil
}

func doStatFuzz(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	path, err := getAvailablePath(fdp)
	if err != nil {
		return err
	}
	_, _ = d.Stat(context.Background(), path)
	return nil
}

func doListFuzz(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	opath, err := getAvailablePath(fdp)
	if err != nil {
		return err
	}
	_, _ = d.List(context.Background(), opath)
	return nil
}

func doMoveFuzz(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	sourcePath, err := getAvailablePath(fdp)
	if err != nil {
		return err
	}
	destPath, err := getAvailablePath(fdp)
	if err != nil {
		return err
	}
	_ = d.Move(context.Background(), sourcePath, destPath)
	return nil
}

func doDeleteFuzz(d *Driver, fdp *fuzz.ConsumeFuzzer) error {
	path, err := getAvailablePath(fdp)
	if err != nil {
		return err
	}
	_ = d.Delete(context.Background(), path)
	return nil
}

func getAvailablePath(fdp *fuzz.ConsumeFuzzer) (string, error) {
	if len(availablePaths) == 0 {
		return "", errors.New("No paths are available")
	}
	index, err := fdp.GetInt()
	if err != nil {
		return "", err
	}
	return availablePaths[index%len(availablePaths)], nil
}
