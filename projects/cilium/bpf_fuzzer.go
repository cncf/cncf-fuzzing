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

package bpf

import (
	"github.com/cilium/ebpf"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"os"
)

var (
	bpffsPath = "bpffFile"
	elfPath   = "elfFile"
	targets   = map[int]string{
		0: "StartBPFFSMigration",
		1: "FinalizeBPFFSMigration",
	}
)

func FuzzBpf(data []byte) int {
	f := fuzz.NewConsumer(data)
	bpffsData, err := f.GetBytes()
	if err != nil {
		return 0
	}

	coll := &ebpf.CollectionSpec{}
	f.GenerateStruct(coll)

	target, err := f.GetInt()
	if err != nil {
		return 0
	}

	// bpff File
	bpffFile, err := os.Create(bpffsPath)
	if err != nil {
		os.Remove(bpffsPath)
		return 0
	}
	defer bpffFile.Close()
	defer os.Remove(bpffsPath)
	bpffFile.Write(bpffsData)
	switch targets[target%len(targets)] {
	case "StartBPFFSMigration":
		StartBPFFSMigration(bpffsPath, coll)
	case "FinalizeBPFFSMigration":
		revert, err := f.GetBool()
		if err != nil {
			return 0
		}
		FinalizeBPFFSMigration(bpffsPath, coll, revert)
	}
	return 1
}