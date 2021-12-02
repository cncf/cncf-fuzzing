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

package intelrdt

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/runc/libcontainer/configs"
)

func FuzzFindMpDir(data []byte) int {
	reader := strings.NewReader(string(data))
	_, err := findIntelRdtMountpointDir(reader)
	if err != nil {
		return 0
	}
	return 1
}

func FuzzParseMonFeatures(data []byte) int {
	_, _ = parseMonFeatures(
		strings.NewReader(string(data)))
	return 1
}

func FuzzSetCacheScema(data []byte) int {
	if (len(data) % 2) != 0 {
		return -1
	}
	halfLen := len(data) / 2
	firstHalf := data[:halfLen]
	secondHalf := data[halfLen:]

	helper, err := NewIntelRdtTestUtil()
	if err != nil {
		return -1
	}
	defer helper.cleanup()

	l3CacheSchemaBefore := string(firstHalf)
	l3CacheSchemeAfter := string(secondHalf)

	err = helper.writeFileContents(map[string]string{
		"schemata": l3CacheSchemaBefore + "\n",
	})
	if err != nil {
		return 0
	}

	helper.IntelRdtData.config.IntelRdt.L3CacheSchema = l3CacheSchemeAfter
	intelrdt := NewManager(helper.IntelRdtData.config, "", helper.IntelRdtPath)
	if err := intelrdt.Set(helper.IntelRdtData.config); err != nil {
		fmt.Println(err)
		return 0
	}

	_, err = getIntelRdtParamString(helper.IntelRdtPath, "schemata")
	if err != nil {
		fmt.Println(err)
		return 0
	}
	return 1
}

type intelRdtTestUtil struct {
	// intelRdt data to use in tests
	IntelRdtData *intelRdtData

	// Path to the mock Intel RDT "resource control" filesystem directory
	IntelRdtPath string

	// Temporary directory to store mock Intel RDT "resource control" filesystem
	tempDir string
}

// Creates a new test util
func NewIntelRdtTestUtil() (*intelRdtTestUtil, error) {
	d := &intelRdtData{
		config: &configs.Config{
			IntelRdt: &configs.IntelRdt{},
		},
	}
	tempDir, err := ioutil.TempDir("", "intelrdt_test")
	if err != nil {
		return nil, err
	}
	testIntelRdtPath := filepath.Join(tempDir, "resctrl")
	if err != nil {
		return nil, err
	}

	// Ensure the full mock Intel RDT "resource control" filesystem path exists
	err = os.MkdirAll(testIntelRdtPath, 0o755)
	if err != nil {
		return nil, err
	}
	return &intelRdtTestUtil{IntelRdtData: d, IntelRdtPath: testIntelRdtPath, tempDir: tempDir}, nil
}

func (c *intelRdtTestUtil) cleanup() {
	os.RemoveAll(c.tempDir)
}

// Write the specified contents on the mock of the specified Intel RDT "resource control" files
func (c *intelRdtTestUtil) writeFileContents(fileContents map[string]string) error {
	for file, contents := range fileContents {
		err := writeFile(c.IntelRdtPath, file, contents)
		if err != nil {
			return err
		}
	}
	return nil
}
