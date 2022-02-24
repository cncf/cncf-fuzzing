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

package repo

import (
	"os"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"helm.sh/helm/v3/pkg/chart"
)

func FuzzIndex(data []byte) int {
	f := fuzz.NewConsumer(data)
	indexFileBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	md := &chart.Metadata{}
	err = f.GenerateStruct(md)
	if err != nil {
		return 0
	}
	filename, err := f.GetString()
	if err != nil {
		return 0
	}
	baseURL, err := f.GetString()
	if err != nil {
		return 0
	}
	digest, err := f.GetString()
	if err != nil {
		return 0
	}
	indf, err := os.Create("indexfile")
	if err != nil {
		return 0
	}
	name, err := f.GetString()
	if err != nil {
		return 0
	}
	version, err := f.GetString()
	if err != nil {
		return 0
	}
	defer indf.Close()
	defer os.Remove("indexfile")
	_, err = indf.Write(indexFileBytes)
	if err != nil {
		return 0
	}
	ind, err := LoadIndexFile("indexfile")
	if err != nil {
		return 0
	}
	ind.MustAdd(md, filename, baseURL, digest)
	ind.Get(name, version)
	return 1
}

func FuzzIndexDirectory(data []byte) int {
	f := fuzz.NewConsumer(data)
	baseURL, err := f.GetString()
	if err != nil {
		return 0
	}

	err = os.Mkdir("indexdir", 0755)
	if err != nil {
		return 0
	}
	defer os.RemoveAll("indexdir")
	err = f.CreateFiles("indexdir")
	if err != nil {
		return 0
	}
	_, _ = IndexDirectory("indexdir", baseURL)
	return 1
}
