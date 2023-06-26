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
package fs

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/cubefs/cubefs/proto"
)

type NewFileParam struct {
	Pino     uint64
	Flag     uint32
	FileName string
	Info     *proto.InodeInfo
	Super    *Super
}

type NewDirParam struct {
	Pino     uint64
	FileName string
	Info     *proto.InodeInfo
	Super    *Super
}

func FuzzNewFile(data []byte) int {
	f := fuzz.NewConsumer(data)
	param := NewFileParam{}

	err := f.GenerateStruct(&param)
	if err != nil {
		return 0
	}

	file := NewFile(param.Super, param.Info, param.Flag, param.Pino, param.FileName)
	if file == nil {
		return 0
	}
	return 1
}

func FuzzNewDir(data []byte) int {
	f := fuzz.NewConsumer(data)
	param := NewDirParam{}

	err := f.GenerateStruct(&param)
	if err != nil {
		return 0
	}

	dir := NewDir(param.Super, param.Info, param.Pino, param.FileName)
	if dir == nil {
		return 0
	}
	return 1
}
