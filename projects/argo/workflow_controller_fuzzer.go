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
