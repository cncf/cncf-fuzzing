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
	"github.com/opencontainers/runc/libcontainer/system"
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
	err = c.GenerateStruct(config)
	if err != nil {
		return 0
	}
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

	container := newContainerWithName()
	if container == nil {
		return 0
	}
	defer container.Destroy()

	err = container.Set(*config)
	if err != nil {
		return 0
	}

	// Fuzz container APIs:
	_, _ = container.State()
	_, _ = container.Stats()
	_, _ = container.OCIState()
	_, _ = container.Processes()

	process := &Process{}
	err = c.GenerateStruct(process)
	if err != nil {
		return 0
	}
	_ = container.Run(process)
	err = container.Pause()
	if err == nil {
		container.Resume()
	}

	process = &Process{}
	err = c.GenerateStruct(process)
	if err != nil {
		return 0
	}

	criuOpts := &CriuOpts{}
	err = c.GenerateStruct(criuOpts)
	if err != nil {
		return 0
	}
	_ = container.Restore(process, criuOpts)

	return 1
}

func newContainerWithName() *Container {
	pid := 1
	stat, err := system.Stat(pid)
	if err != nil {
		return nil
	}
	container := &Container{
		id:     "myid",
		config: &configs.Config{},
		cgroupManager: &mockCgroupManager{
			allPids: []int{1, 2, 3},
			paths: map[string]string{
				"device": "/proc/self/cgroups",
			},
		},
		initProcess: &mockProcess{
			_pid:    1,
			started: 10,
		},
		initProcessStartTime: stat.StartTime,
	}
	container.state = &runningState{c: container}
	return container
}

func newTestRoot() (string, error) {
	dir := "/tmp/fuzzing"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}
