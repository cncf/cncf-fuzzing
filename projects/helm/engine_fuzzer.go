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
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"

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
