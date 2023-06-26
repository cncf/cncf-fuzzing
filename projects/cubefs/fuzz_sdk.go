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
package meta

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzNewMeta(data []byte) int {
	f := fuzz.NewConsumer(data)
	config := MetaConfig{}

	err := f.GenerateStruct(&config)
	if err != nil {
		return 0
	}

	_, err = NewMetaWrapper(&config)
	if err != nil {
		return 0
	}
	return 1
}
