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

package specconv

import (
	"io/ioutil"
	"os"

	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
)

func newTestRoot(name string) (string, error) {
	dir, err := ioutil.TempDir("", name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func Fuzz(data []byte) int {
	if len(data) < 30 {
		return -1
	}
	f := gofuzzheaders.NewConsumer(data)
	linuxSpec := new(specs.Linux)
	err := f.GenerateStruct(linuxSpec)
	if err != nil {
		return 0
	}

	// Create spec.Spec
	spec := new(specs.Spec)
	err = f.GenerateStruct(spec)
	if err != nil {
		return 0
	}
	spec.Linux = linuxSpec

	// Create CreateOpts
	opts := new(CreateOpts)
	err = f.GenerateStruct(opts)
	if err != nil {
		return 0
	}
	opts.Spec = spec

	config := &configs.Resources{}
	err = f.GenerateStruct(config)
	if err != nil {
		return 0
	}

	c, err := CreateCgroupConfig(opts, nil)
	if err != nil {
		return 0
	}

	path, err := newTestRoot("fuzzDir")
	if err != nil {
		return 0
	}
	um, err := systemd.NewUnifiedManager(c, path)
	if err != nil {
		return 0
	}
	err = um.Set(config)
	err = um.Apply(int(data[0]))
	err = um.Destroy()
	return 1
}
