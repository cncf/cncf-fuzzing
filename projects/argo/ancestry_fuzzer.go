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

package common

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	wfv1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	"runtime"
	"strings"
	"time"
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
		if strings.Contains(err, "The task was nil.") {
			return
		} else {
			panic(err)
		}
	}
}

type testFuzzContext struct {
	status    map[string]time.Time
	testTasks []*wfv1.DAGTask
}

func (d *testFuzzContext) GetTask(taskName string) *wfv1.DAGTask {
	for _, task := range d.testTasks {
		if task.Name == taskName {
			return task
		}
	}
	panic("The task was nil.")
	return nil
}

func (d *testFuzzContext) GetTaskDependencies(taskName string) []string {
	return d.GetTask(taskName).Dependencies
}

func (d *testFuzzContext) GetTaskFinishedAtTime(taskName string) time.Time {
	if finished, ok := d.status[taskName]; ok {
		return finished
	}
	return time.Now()
}

func FuzzGetTaskDependencies(data []byte) int {
	f := fuzz.NewConsumer(data)
	task := &wfv1.DAGTask{}
	err := f.GenerateStruct(task)
	if err != nil {
		return 0
	}

	numOfTestTasks, err := f.GetInt()
	if err != nil {
		return 0
	}
	testTasks := make([]*wfv1.DAGTask, 0)
	for i := 0; i < numOfTestTasks%10; i++ {
		testTask := &wfv1.DAGTask{}
		err = f.GenerateStruct(testTask)
		if err != nil {
			return 0
		}
		testTasks = append(testTasks, testTask)
	}
	ctx := &testFuzzContext{
		testTasks: testTasks,
	}
	defer catchPanics()
	_, _ = GetTaskDependencies(task, ctx)
	return 1
}
