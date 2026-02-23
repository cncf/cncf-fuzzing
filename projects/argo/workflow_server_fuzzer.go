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

package workflow

import (
	"context"
	"encoding/json"
	"testing"

	workflowpkg "github.com/argoproj/argo-workflows/v3/pkg/apiclient/workflow"
)

func getWorkflowServerFuzz() (workflowpkg.WorkflowServiceServer, context.Context) {
	var server workflowpkg.WorkflowServiceServer
	var ctx context.Context
	tests := []testing.InternalTest{
		{
			Name: "FuzzHelper",
			F: func(t *testing.T) {
				server, ctx = getWorkflowServer(t)
			},
		},
	}
	testing.RunTests(func(pat, str string) (bool, error) { return true, nil }, tests)
	return server, ctx
}

func FuzzWorkflowServer(data []byte) int {
	// Recover from panics in testing.RunTests infrastructure which can
	// crash in the go-fuzz binary context (see also: disabled artifacts fuzzers)
	defer func() { recover() }()

	var req1 workflowpkg.WorkflowCreateRequest
	err := json.Unmarshal(data, &req1)
	if err != nil {
		return 0
	}

	server, ctx := getWorkflowServerFuzz()

	// Always create the workflow first so other operations have something to work with
	createdWf, createErr := server.CreateWorkflow(ctx, &req1)

	// List workflows regardless of creation result
	_, _ = server.ListWorkflows(ctx, &workflowpkg.WorkflowListRequest{})
	_, _ = server.LintWorkflow(ctx, &workflowpkg.WorkflowLintRequest{Workflow: req1.Workflow})

	// If creation succeeded, perform operations on the created workflow
	if createErr == nil && createdWf != nil {
		name := createdWf.Name
		ns := createdWf.Namespace

		_, _ = server.GetWorkflow(ctx, &workflowpkg.WorkflowGetRequest{Name: name, Namespace: ns})
		_, _ = server.SuspendWorkflow(ctx, &workflowpkg.WorkflowSuspendRequest{Name: name, Namespace: ns})
		_, _ = server.ResumeWorkflow(ctx, &workflowpkg.WorkflowResumeRequest{Name: name, Namespace: ns})
		_, _ = server.RetryWorkflow(ctx, &workflowpkg.WorkflowRetryRequest{Name: name, Namespace: ns})
		_, _ = server.ResubmitWorkflow(ctx, &workflowpkg.WorkflowResubmitRequest{Name: name, Namespace: ns})
		_, _ = server.SetWorkflow(ctx, &workflowpkg.WorkflowSetRequest{Name: name, Namespace: ns})
		_, _ = server.StopWorkflow(ctx, &workflowpkg.WorkflowStopRequest{Name: name, Namespace: ns})
		_, _ = server.TerminateWorkflow(ctx, &workflowpkg.WorkflowTerminateRequest{Name: name, Namespace: ns})
		_, _ = server.SubmitWorkflow(ctx, &workflowpkg.WorkflowSubmitRequest{Namespace: ns})
		// Delete last since it removes the workflow
		_, _ = server.DeleteWorkflow(ctx, &workflowpkg.WorkflowDeleteRequest{Name: name, Namespace: ns})
	}

	return 1
}
