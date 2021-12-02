//go:build gofuzz
// +build gofuzz

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

package libcontainer

import (
	"os"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/sirupsen/logrus"
)

func FuzzStateApi(data []byte) int {
	// We do not want any log output:
	logrus.SetLevel(logrus.PanicLevel)

	if len(data) < 4 {
		return -1
	}

	// Create the root dir:
	root, err := newTestRoot()
	if err != nil {
		return -1
	}
	defer os.RemoveAll(root)

	// Create a fuzzconsumer for later user
	c := gofuzzheaders.NewConsumer(data)

	// Create a config
	config := new(configs.Config)
	c.GenerateStruct(config)
	config.Rootfs = root

	// Add Namespaces:
	ns, err := c.GetInt()
	if err != nil {
		return -1
	}
	if (ns % 3) == 0 {
		config.Namespaces = configs.Namespaces(
			[]configs.Namespace{
				{Type: configs.NEWUTS},
			},
		)
	} else if (ns % 4) == 0 {
		config.Namespaces = configs.Namespaces(
			[]configs.Namespace{
				{Type: configs.NEWNS},
			},
		)
	} else {
		config.Namespaces = []configs.Namespace{}
	}

	// Create container:
	containerName, err := c.GetString()
	if err != nil {
		return 0
	}
	container, err := newContainerWithName(containerName, root, config)
	if err != nil {
		return 0
	}
	defer container.Destroy()

	// Fuzz container APIs:
	_, _ = container.State()
	_, _ = container.Stats()
	_, _ = container.OCIState()
	_, _ = container.Processes()
	return 1
}

func newContainerWithName(name, root string, config *configs.Config) (Container, error) {
	f, err := New(root)
	if err != nil {
		return nil, err
	}
	if config.Cgroups != nil && config.Cgroups.Parent == "system.slice" {
		f, err = New(root)
		if err != nil {
			return nil, err
		}
	}
	return f.Create(name, config)
}

func newTestRoot() (string, error) {
	dir := "/tmp/fuzzing"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}
