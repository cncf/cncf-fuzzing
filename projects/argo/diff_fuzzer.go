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

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	appstatecache "github.com/argoproj/argo-cd/v2/util/cache/appstate"
	"github.com/argoproj/argo-cd/v2/util/argo/normalizers"

	"github.com/ghodss/yaml"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type diffConfigParams struct {
	ignores        []v1alpha1.ResourceIgnoreDifferences
	overrides      map[string]v1alpha1.ResourceOverride
	label          string
	trackingMethod string
	noCache        bool
	ignoreRoles    bool
	appName        string
	stateCache     *appstatecache.Cache
}

func defaultDiffConfigParams() *diffConfigParams {
	return &diffConfigParams{
		ignores:        []v1alpha1.ResourceIgnoreDifferences{},
		overrides:      map[string]v1alpha1.ResourceOverride{},
		label:          "",
		trackingMethod: "",
		noCache:        true,
		ignoreRoles:    true,
		appName:        "",
		stateCache:     &appstatecache.Cache{},
	}
}

func diffConfigFuzz(params *diffConfigParams) (DiffConfig, error) {
	diffConfig, err := NewDiffConfigBuilder().
		WithDiffSettings(params.ignores, params.overrides, params.ignoreRoles, normalizers.IgnoreNormalizerOpts{}).
		WithTracking(params.label, params.trackingMethod).
		WithNoCache().
		Build()
	if err != nil {
		return nil, err
	}
	return diffConfig, nil
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

func YamlToUnstructured(yamlStr string) (*unstructured.Unstructured, error) {
	obj := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(yamlStr), &obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: obj}, nil
}

func FuzzStateDiff(data []byte) int {
	defer catchPanics()
	f := fuzz.NewConsumer(data)
	liveStateString, err := f.GetString()
	if err != nil {
		return 0
	}
	desiredStateString, err := f.GetString()
	if err != nil {
		return 0
	}
	liveState, err := YamlToUnstructured(liveStateString)
	if err != nil {
		return 0
	}
	desiredState, err := YamlToUnstructured(desiredStateString)
	if err != nil {
		return 0
	}
	dc, err := diffConfigFuzz(defaultDiffConfigParams())
	if err != nil {
		return 0
	}
	_, _ = StateDiff(liveState, desiredState, dc)
	return 1
}
