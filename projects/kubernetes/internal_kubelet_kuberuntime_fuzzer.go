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

package kuberuntime

import (
	"context"
	v1 "k8s.io/api/core/v1"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzKubeRuntime(data []byte) int {
	f := fuzz.NewConsumer(data)
	pod := &v1.Pod{}
	status := &kubecontainer.PodStatus{}
	err := f.GenerateStruct(pod)
	if err != nil {
		return 0
	}
	err = f.GenerateStruct(status)
	if err != nil {
		return 0
	}
	_, _, m, err := createTestRuntimeManager(context.Background())
	if err != nil {
		return 0
	}
	restartAll, err := f.GetBool()
	if err != nil {
		restartAll = false
	}
	_ = m.computePodActions(context.Background(), pod, status, restartAll)
	return 1
}
