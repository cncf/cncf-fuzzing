// Copyright 2021 ADA Logics Ltd
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

package diff

import (
	"runtime"
	"strings"

	fuzz "github.com/AdamKorcz/go-fuzz-headers"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func bytesToUnstructuredFuzz(jsonBytes []byte) (*unstructured.Unstructured, error) {
	obj := make(map[string]interface{})
	err := yaml.Unmarshal(jsonBytes, &obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: obj}, nil
}

func catchPanics() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case runtime.Error:
			err = r.(runtime.Error).Error()
		case error:
			err = r.(error).Error()
		}
		if strings.Contains(err, "Object 'Kind' is missing in") {
			return
		} else {
			panic(err)
		}
	}
}

func FuzzGitopsDiff(data []byte) int {
	defer catchPanics()
	f := fuzz.NewConsumer(data)

	numItemsConfigArray, err := f.GetInt()
	if err != nil {
		return 0
	}
	configArray := make([]*unstructured.Unstructured, 0)
	for i := 0; i < numItemsConfigArray%30; i++ {
		usBytes, err := f.GetBytes()
		if err != nil {
			return 0
		}
		us, err := bytesToUnstructuredFuzz(usBytes)
		if err != nil {
			return 0
		}
		configArray = append(configArray, us)
	}

	numItemsLiveArray, err := f.GetInt()
	if err != nil {
		return 0
	}
	liveArray := make([]*unstructured.Unstructured, 0)
	for i := 0; i < numItemsLiveArray%30; i++ {
		usBytes, err := f.GetBytes()
		if err != nil {
			return 0
		}
		us, err := bytesToUnstructuredFuzz(usBytes)
		if err != nil {
			return 0
		}
		liveArray = append(liveArray, us)
	}
	_, _ = DiffArray(configArray, liveArray)

	// Test individual Diff
	if configBytes, err := f.GetBytes(); err == nil {
		if config, err := bytesToUnstructuredFuzz(configBytes); err == nil {
			if liveBytes, err := f.GetBytes(); err == nil {
				if live, err := bytesToUnstructuredFuzz(liveBytes); err == nil {
					_, _ = Diff(config, live)
				}
			}
		}
	}

	// Test ThreeWayDiff
	if origBytes, err := f.GetBytes(); err == nil {
		if orig, err := bytesToUnstructuredFuzz(origBytes); err == nil {
			if configBytes, err := f.GetBytes(); err == nil {
				if config, err := bytesToUnstructuredFuzz(configBytes); err == nil {
					if liveBytes, err := f.GetBytes(); err == nil {
						if live, err := bytesToUnstructuredFuzz(liveBytes); err == nil {
							_, _ = ThreeWayDiff(orig, config, live)
						}
					}
				}
			}
		}
	}

	// Test Normalize
	if normBytes, err := f.GetBytes(); err == nil {
		if un, err := bytesToUnstructuredFuzz(normBytes); err == nil {
			Normalize(un)
		}
	}

	return 1
}
