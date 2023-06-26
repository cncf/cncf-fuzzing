//go:build gofuzz
// +build gofuzz

// Copyright 2023 ADA Logics Ltd
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
package datanode

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

type NewDiskParam struct {
	Path            string
	ReservedSpace   uint64
	DiskRdonlySpace uint64
	MaxErrCnt       int
	Space           *SpaceManager
}

func FuzzNewDisk(data []byte) int {
	f := fuzz.NewConsumer(data)
	param := NewDiskParam{}

	err := f.GenerateStruct(&param)
	if err != nil {
		return 0
	}

	disk, err := NewDisk(param.Path, param.ReservedSpace, param.DiskRdonlySpace, param.MaxErrCnt, param.Space)
	if disk == nil {
		return 0
	}

	if err != nil {
		return 0
	}
	return 1
}
