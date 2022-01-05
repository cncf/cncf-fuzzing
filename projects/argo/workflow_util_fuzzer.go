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

package util

import (
	"context"
	"reflect"
	"runtime"
	"strings"

	wfv1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	argofake "github.com/argoproj/argo-workflows/v3/pkg/client/clientset/versioned/fake"
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

func FuzzSubmitWorkflow(data []byte) int {
	defer catchPanics()
	ctx := context.Background()
	wf := wfv1.MustUnmarshalWorkflow(data)
	newWf := wf.DeepCopy()
	wfClientSet := argofake.NewSimpleClientset()
	newWf, err := SubmitWorkflow(ctx, nil, wfClientSet, "test-namespace", newWf, &wfv1.SubmitOpts{DryRun: true})
	if err != nil {
		return 0
	}
	if !reflect.DeepEqual(wf.Spec, newWf.Spec) {
		panic("Spec should be equal but is not")
	}
	if !reflect.DeepEqual(wf.Status, newWf.Status) {
		panic("Status should be equal but is not")
	}
	return 1
}
