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

package engine

import (
	chart "helm.sh/helm/v4/pkg/chart/v2"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzEngineRender(data []byte) int {
	f := fuzz.NewConsumer(data)
	chrt := &chart.Chart{}
	err := f.GenerateStruct(chrt)
	if err != nil {
		return 0
	}
	valuesBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	values, err := chartutil.ReadValues(valuesBytes)
	if err != nil {
		return 0
	}
	_, _ = Render(chrt, values)
	return 1
}

func FuzzEngineFiles(data []byte) int {
	f := fuzz.NewConsumer(data)
	noOfEntries, err := f.GetInt()
	if err != nil {
		return 0
	}
	files := make(files, 0)
	for i:=0;i<noOfEntries%15;i++ {
		name, err := f.GetString()
		if err != nil {
			return 0
		}
		byteData, err := f.GetBytes()
		if err != nil {
			return 0
		}
		files[name] = byteData
	}
	name, err := f.GetString()
	if err != nil {
		return 0
	}
	_ = files.Get(name)
	pattern, err := f.GetString()
	if err != nil {
		return 0
	}
	_ = files.Glob(pattern)
	_ = files.AsConfig()
	_ = files.AsSecrets()

	path, err := f.GetString()
	if err != nil {
		return 0
	}
	_ = files.Lines(path)
	return 1
}
