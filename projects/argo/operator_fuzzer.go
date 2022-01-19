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

package controller

import (
	"context"
	"runtime"
	"strings"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	wfv1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
)

func catchOperatorPanics() {
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
		if strings.Contains(err, "failed to convert to unstructured: error decoding from json: empty value") {
			return
		} else if strings.Contains(err, "failed to convert to unstructured: error decoding number from json") {
			return
		} else if strings.Contains(err, "error calling MarshalJSON for type *v1alpha1.Item: invalid character") {
			return
		} else {
			panic(err)
		}
	}
}

func FuzzOperator(data []byte) int {
	f := fuzz.NewConsumer(data)
	wf := &wfv1.Workflow{}
	err := f.GenerateStruct(wf)
	if err != nil {
		return 0
	}
	defer catchOperatorPanics()
	cancel, controller := newController(wf)
	defer cancel()
	ctx := context.Background()
	woc := newWorkflowOperationCtx(wf, controller)
	woc.operate(ctx)
	return 1
}
