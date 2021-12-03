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

package fs2

import (
	"bytes"
	"errors"
	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"os"
)

func FuzzCgroupReader(data []byte) int {
	r := bytes.NewReader(data)
	_, _ = parseCgroupFromReader(r)
	return 1
}

func createFiles(files []string, cf *gofuzzheaders.ConsumeFuzzer) error {
	for i := 0; i < len(files); i++ {
		f, err := os.OpenFile(files[i], os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			return errors.New("Could not create file")
		}
		defer f.Close()
		//defer os.RemoveAll(files[i])
		b, err := cf.GetBytes()
		if err != nil {
			return errors.New("Could not get bytes")
		}
		_, err = f.Write(b)
		if err != nil {
			return errors.New("Could not write to file")
		}
	}
	return nil
}

func FuzzGetStats(data []byte) int {
	stats := cgroups.Stats{}
	f := gofuzzheaders.NewConsumer(data)
	err := f.GenerateStruct(&stats)
	if err != nil {
		return -1
	}

	// statPids:
	sPidsFiles := []string{"/tmp/pids.current",
		"/tmp/pids.max"}
	err = createFiles(sPidsFiles, f)
	if err != nil {
		return -1
	}
	defer os.RemoveAll("/tmp/pids.current")
	defer os.RemoveAll("/tmp/pids.max")
	_ = statPids("/tmp", &stats)

	// statMemory:
	stats3 := cgroups.Stats{}
	err = f.GenerateStruct(&stats3)
	if err != nil {
		return -1
	}
	sMemFiles := []string{"/tmp/memory.stat",
		"/tmp/memory.swap",
		"/tmp/memory.current",
		"/tmp/memory.max"}
	err = createFiles(sMemFiles, f)
	if err != nil {
		return -1
	}
	defer os.RemoveAll("/tmp/memory.stat")
	defer os.RemoveAll("/tmp/memory.swap")
	defer os.RemoveAll("/tmp/memory.current")
	defer os.RemoveAll("/tmp/memory.max")
	_ = statMemory("/tmp", &stats3)

	// StatIo:
	stats4 := cgroups.Stats{}
	err = f.GenerateStruct(&stats4)
	if err != nil {
		return -1
	}
	sIoFiles := []string{"/tmp/io.stat"}
	err = createFiles(sIoFiles, f)
	if err != nil {
		return -1
	}
	defer os.RemoveAll("/tmp/io.stat")
	_ = statIo("/tmp", &stats4)

	// statCpu:
	stats5 := cgroups.Stats{}
	err = f.GenerateStruct(&stats5)
	if err != nil {
		return -1
	}
	sCpuFiles := []string{"/tmp/cpu.stat"}
	err = createFiles(sCpuFiles, f)
	if err != nil {
		return -1
	}
	defer os.RemoveAll("/tmp/cpu.stat")
	_ = statCpu("/tmp", &stats5)
	return 1
}
