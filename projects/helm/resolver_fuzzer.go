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

package resolver

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/registry"
	"os"
)

func FuzzResolve(data []byte) int {
	f := fuzz.NewConsumer(data)
	noOfDeps, err := f.GetInt()
	if err != nil {
		return 0
	}
	deps := make([]*chart.Dependency, 0)
	for i := 0; i < noOfDeps%10; i++ {
		dep := &chart.Dependency{}
		err := f.GenerateStruct(dep)
		if err != nil {
			return 0
		}
		deps = append(deps, dep)
	}
	chartPath := "chartPath"
	os.Mkdir(chartPath, 0755)
	defer os.RemoveAll(chartPath)
	err = f.CreateFiles(chartPath)
	if err != nil {
		return 0
	}

	repository := "repository"
	os.Mkdir(repository, 0755)
	defer os.RemoveAll(repository)
	err = f.CreateFiles(repository)
	if err != nil {
		return 0
	}

	repoNames := make(map[string]string)
	err = f.FuzzMap(&repoNames)
	if err != nil {
		return 0
	}

	registryClient, _ := registry.NewClient()
	r := New(chartPath, repository, registryClient)

	_, _ = r.Resolve(deps, repoNames)
	return 1
}
