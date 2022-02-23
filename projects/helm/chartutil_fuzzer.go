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

package chartutil

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"helm.sh/helm/v3/pkg/chart"
)

func FuzzProcessDependencies(data []byte) int {
	f := fuzz.NewConsumer(data)
	valuesBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	vals, err := ReadValues(valuesBytes)
	if err != nil {
		return 0
	}
	c := &chart.Chart{}
	err = f.GenerateStruct(c)
	if err != nil {
		return 0
	}
	ProcessDependencies(c, vals)
	return 1
}
