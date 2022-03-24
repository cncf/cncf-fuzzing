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

package releaseutil

import (
	"helm.sh/helm/v3/pkg/chartutil"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzSplitManifests(data []byte) int {
	_ = SplitManifests(string(data))
	return 1
}

func FuzzSortManifests(data []byte) int {
	f := fuzz.NewConsumer(data)
	files := make(map[string]string)
	err := f.FuzzMap(&files)
	if err != nil {
		return 0
	}
	_, _, _ = SortManifests(files, chartutil.VersionSet{"v1", "v1beta1"}, InstallOrder)
	return 1
}