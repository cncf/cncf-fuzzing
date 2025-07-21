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

package util

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	chart "helm.sh/helm/v4/pkg/chart/v2"
	"os"
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

func FuzzIsChartDir(data []byte) int {
	err := os.Mkdir("fuzzdir", 0755)
	if err != nil {
		return 0
	}
	defer os.RemoveAll("fuzzdir")
	f := fuzz.NewConsumer(data)
	err = f.CreateFiles("fuzzdir")
	if err != nil {
		return 0
	}
	_, _ = IsChartDir("fuzzdir")
	return 1
}

func FuzzExpandFile(data []byte) int {
	fuzzFile, err := os.Create("fuzzFile")
	if err != nil {
		return 0
	}
	defer fuzzFile.Close()
	defer os.Remove(fuzzFile.Name())
	_, err = fuzzFile.Write(data)
	if err != nil {
		return 0
	}
	err = os.Mkdir("fuzzDir", 0755)
	if err != nil {
		return 0
	}
	defer os.RemoveAll("fuzzdir")
	_ = ExpandFile("fuzzDir", fuzzFile.Name())
	return 1
}

func FuzzCreateFrom(data []byte) int {
	f := fuzz.NewConsumer(data)
	md := &chart.Metadata{}
	err := f.GenerateStruct(md)
	if err != nil {
		return 0
	}
	err = os.Mkdir("fuzzDir1", 0755)
	if err != nil {
		return 0
	}
	defer os.RemoveAll("fuzzdir1")
	err = os.Mkdir("fuzzDir2", 0755)
	if err != nil {
		return 0
	}
	defer os.RemoveAll("fuzzDir2")
	err = f.CreateFiles("fuzzDir2")
	if err != nil {
		return 0
	}
	_ = CreateFrom(md, "fuzzDir1", "fuzzDir2")
	return 1
}
