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
        wfv1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
)

// We ignore these panics, as they don't represent real bugs.
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
                if strings.Contains(err, "failed to unmarshal JSON") {
                        return
                }else if strings.Contains(err, "failed to unmarshal YAML") {
                        return
                }else if strings.Contains(err, "failed to read file") {
                        return
                } else {
                        panic(err)
                }
        }
}

func FuzzWorkflowController(data []byte) int {
        defer catchPanics()
        if len(data)<5 {
                return 0
        }
        wf := wfv1.MustUnmarshalWorkflow(string(data))
        if wf==nil {
                return 0
        }
        cancel, controller := newController(wf)
        defer cancel()

        ctx := context.Background()
        woc := newWorkflowOperationCtx(wf, controller)
        woc.operate(ctx)
        return 1
}
