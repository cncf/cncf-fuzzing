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

package cron

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/argoproj/argo-workflows/v3/pkg/client/clientset/versioned/fake"
	"github.com/argoproj/argo-workflows/v3/util/logging"
	"github.com/argoproj/argo-workflows/v3/util/telemetry"
	"github.com/argoproj/argo-workflows/v3/workflow/metrics"
	"github.com/argoproj/argo-workflows/v3/workflow/templateresolution"
	"github.com/argoproj/argo-workflows/v3/workflow/validate"
)

var (
	cronWfClientset   = fake.NewSimpleClientset()
	cronWftmplGetter  = templateresolution.WrapWorkflowTemplateInterface(cronWfClientset.ArgoprojV1alpha1().WorkflowTemplates(metav1.NamespaceDefault))
	cronCwftmplGetter = templateresolution.WrapClusterWorkflowTemplateInterface(cronWfClientset.ArgoprojV1alpha1().ClusterWorkflowTemplates())
)

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

func FuzzWoCRun(data []byte) int {
	defer catchPanics()
	var cronWf v1alpha1.CronWorkflow
	v1alpha1.MustUnmarshal(data, &cronWf)

	cs := fake.NewSimpleClientset()
	ctx := logging.NewSlogLogger(logging.Info, logging.Text).NewBackgroundContext()
	testMetrics, err := metrics.New(ctx, telemetry.TestScopeName, telemetry.TestScopeName, &telemetry.Config{}, metrics.Callbacks{})
	if err != nil {
		panic(err)
	}
	woc := &cronWfOperationCtx{
		wfClientset:       cs,
		wfClient:          cs.ArgoprojV1alpha1().Workflows(""),
		cronWfIf:          cs.ArgoprojV1alpha1().CronWorkflows(""),
		cronWf:            &cronWf,
		log:               logging.NewSlogLogger(logging.Info, logging.Text),
		metrics:           testMetrics,
		scheduledTimeFunc: inferScheduledTime,
		ctx:               ctx,
	}
	woc.Run()
	return 1
}

func FuzzCronValidation(data []byte) int {
	defer catchPanics()
	var cronWf v1alpha1.CronWorkflow
	v1alpha1.MustUnmarshal(data, &cronWf)
	ctx := logging.NewSlogLogger(logging.Info, logging.Text).NewBackgroundContext()
	_ = validate.CronWorkflow(ctx, cronWftmplGetter, cronCwftmplGetter, &cronWf, nil)
	return 1
}
