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
        "strings"
        wfv1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
        "github.com/argoproj/argo-workflows/v3/util/logging"
)

// catchPanics recovers from expected MustUnmarshal panics.
func catchPanics() {
        if r := recover(); r != nil {
                var msg string
                switch v := r.(type) {
                case string:
                        msg = v
                case error:
                        msg = v.Error()
                default:
                        panic(r)
                }
                if strings.Contains(msg, "unmarshal") || strings.Contains(msg, "failed to read file") {
                        return
                }
                panic(r)
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
        ctx := logging.NewSlogLogger(logging.Info, logging.Text).NewBackgroundContext()
        cancel, controller := newController(ctx, wf)
        defer cancel()

        woc := newWorkflowOperationCtx(ctx, wf, controller)
        woc.operate(ctx)
        return 1
}
