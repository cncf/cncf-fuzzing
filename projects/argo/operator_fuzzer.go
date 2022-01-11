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
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	wfv1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
)

func FuzzOperator(data []byte) int {
	f := fuzz.NewConsumer(data)
	wf := &wfv1.Workflow{}
	err := f.GenerateStruct(wf)
	if err != nil {
		return 0
	}
	cancel, controller := newController(wf)
	defer cancel()
	ctx := context.Background()
	woc := newWorkflowOperationCtx(wf, controller)
	woc.operate(ctx)
	return 1
}
