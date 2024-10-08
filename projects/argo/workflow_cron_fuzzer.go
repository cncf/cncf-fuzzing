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
	"context"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"github.com/argoproj/argo-workflows/v3/pkg/client/clientset/versioned/fake"
	"github.com/argoproj/argo-workflows/v3/workflow/metrics"
	"github.com/argoproj/argo-workflows/v3/util/telemetry"
)

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
		} else if strings.Contains(err, "failed to unmarshal YAML") {
			return
		} else if strings.Contains(err, "failed to read file") {
			return
		} else if strings.Contains(err, "no text to unmarshal") {
			return
		} else {
			panic(err)
		}
	}
}

func FuzzWoCRun(data []byte) int {
	defer catchPanics()
	var cronWf v1alpha1.CronWorkflow
	v1alpha1.MustUnmarshal(data, &cronWf)

	cs := fake.NewSimpleClientset()
	testMetrics, err := metrics.New(context.Background(), telemetry.TestScopeName, telemetry.TestScopeName, &telemetry.Config{}, metrics.Callbacks{})
	if err != nil {
		panic(err)
	}
	woc := &cronWfOperationCtx{
		wfClientset:       cs,
		wfClient:          cs.ArgoprojV1alpha1().Workflows(""),
		cronWfIf:          cs.ArgoprojV1alpha1().CronWorkflows(""),
		cronWf:            &cronWf,
		log:               logrus.WithFields(logrus.Fields{}),
		metrics:           testMetrics,
		scheduledTimeFunc: inferScheduledTime,
	}
	woc.Run()
	return 1
}
