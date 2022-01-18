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
	workflowpkg "github.com/argoproj/argo-workflows/v3/pkg/apiclient/workflow"
)

func FuzzWorkflowServer(data []byte) int {
	var server workflowpkg.WorkflowServiceServer
	var ctx context.Context

	var req1 workflowpkg.WorkflowCreateRequest
	err := json.Unmarshal(data, &req1)
	if err == nil {
		server, ctx = getWorkflowServer()
		_, _ = server.CreateWorkflow(ctx, &req1)
	}

	var req2 workflowpkg.WorkflowGetRequest
	err = json.Unmarshal(data, &req2)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.GetWorkflow(ctx, &req2)
	}

	var req3 workflowpkg.WorkflowListRequest
	err = json.Unmarshal(data, &req3)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.ListWorkflows(ctx, &req3)
	}

	var req4 workflowpkg.WorkflowDeleteRequest
	err = json.Unmarshal(data, &req4)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.DeleteWorkflow(ctx, &req4)
	}

	var req5 workflowpkg.WorkflowRetryRequest
	err = json.Unmarshal(data, &req5)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.RetryWorkflow(ctx, &req5)
	}

	var req6 workflowpkg.WorkflowResubmitRequest
	err = json.Unmarshal(data, &req6)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.ResubmitWorkflow(ctx, &req6)
	}

	var req7 workflowpkg.WorkflowResumeRequest
	err = json.Unmarshal(data, &req7)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.ResumeWorkflow(ctx, &req7)
	}

	var req8 workflowpkg.WorkflowSuspendRequest
	err = json.Unmarshal(data, &req8)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.SuspendWorkflow(ctx, &req8)
	}

	var req9 workflowpkg.WorkflowTerminateRequest
	err = json.Unmarshal(data, &req9)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.TerminateWorkflow(ctx, &req9)
	}

	var req10 workflowpkg.WorkflowStopRequest
	err = json.Unmarshal(data, &req10)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.StopWorkflow(ctx, &req10)
	}

	var req11 workflowpkg.WorkflowSetRequest
	err = json.Unmarshal(data, &req11)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.SetWorkflow(ctx, &req11)
	}

	var req12 workflowpkg.WorkflowLintRequest
	err = json.Unmarshal(data, &req12)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.LintWorkflow(ctx, &req12)
	}

	var req13 workflowpkg.WorkflowSubmitRequest
	err = json.Unmarshal(data, &req13)
	if err == nil {
		if server == nil {
			server, ctx = getWorkflowServer()
		}
		_, _ = server.SubmitWorkflow(ctx, &req13)
	}

	return 1
}
