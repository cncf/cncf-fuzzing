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

package analysis

import (
	"testing"
	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzreconcileAnalysisRun(data []byte) int {
	f := fuzz.NewConsumer(data)
	run := &v1alpha1.AnalysisRun{}
	err := f.GenerateStruct(run)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	fi := newFixture(t)
	defer fi.Close()
	c, _, _ := fi.newController(noResyncPeriodFunc)
	_ = c.reconcileAnalysisRun(run)
	return 1
}