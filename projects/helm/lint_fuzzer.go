//go:build gofuzz
// +build gofuzz

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

package lint

import (
	"os"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzLintAll(data []byte) int {
	f := fuzz.NewConsumer(data)

	err := os.Mkdir("fuzzDir", 0755)
	if err != nil {
		return 0
	}
	defer os.RemoveAll("fuzzDir")
	err = f.CreateFiles("fuzzDir")
	if err != nil {
		return 0
	}
	var values map[string]interface{}
	_ = RunAll("fuzzDir", values, "fuzzNamespace")
	return 1
}
