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

package action

import (
	"fmt"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"helm.sh/helm/v3/pkg/chart"
	kubefake "helm.sh/helm/v3/pkg/kube/fake"
	"helm.sh/helm/v3/pkg/release"
	"testing"
)

func FuzzActionRun(data []byte) int {
	f := fuzz.NewConsumer(data)
	newChart := &chart.Chart{}
	err := f.GenerateStruct(newChart)
	if err != nil {
		return 0
	}

	t := &testing.T{}
	rel := &release.Release{}
	err = f.GenerateStruct(rel)
	if err != nil {
		return 0
	}

	upAction := upgradeAction(t)
	upAction.cfg.Releases.Create(rel)

	failer := upAction.cfg.KubeClient.(*kubefake.FailingKubeClient)
	failer.WaitError = fmt.Errorf("I timed out")
	failer.DeleteError = fmt.Errorf("I tried to delete nil")
	upAction.cfg.KubeClient = failer
	upAction.Wait = true
	upAction.CleanupOnFail = true
	vals := map[string]interface{}{}

	_, _ = upAction.Run(rel.Name, newChart, vals)
	return 1
}

func FuzzShowRun(data []byte) int {
	client := NewShow(ShowAll)
	newChart := &chart.Chart{}

	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(newChart)
	if err != nil {
		return 0
	}

	client.chart = newChart
	_, _ = client.Run("")
	return 1
}
