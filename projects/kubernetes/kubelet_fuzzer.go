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

package fuzzing

import (
	"bytes"
	"context"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"k8s.io/api/core/v1"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	apitesting "k8s.io/cri-api/pkg/apis/testing"
	"k8s.io/kubernetes/pkg/kubelet/kubeletconfig/checkpoint"
	"k8s.io/kubernetes/pkg/kubelet/kuberuntime/logs"
	"os"
	"time"
)

func FuzzDecodeRemoteConfigSource(data []byte) int {
	_, _ = checkpoint.DecodeRemoteConfigSource(data)
	return 1
}

func FuzzReadLogs(data []byte) int {
	f := fuzz.NewConsumer(data)
	logFileBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	logFile, err := os.Create("/tmp/logfile")
	if err != nil {
		return 0
	}
	defer logFile.Close()
	_, err = logFile.Write(logFileBytes)
	if err != nil {
		return 0
	}

	containerID := "fake-container-id"

	podLogOptions := &v1.PodLogOptions{}
	err = f.GenerateStruct(podLogOptions)
	if err != nil {
		return 0
	}

	fakeRuntimeService := &apitesting.FakeRuntimeService{
		Containers: map[string]*apitesting.FakeContainer{
			containerID: {
				ContainerStatus: runtimeapi.ContainerStatus{
					State: runtimeapi.ContainerState_CONTAINER_RUNNING,
				},
			},
		},
	}
	// If follow is specified, mark the container as exited or else ReadLogs will run indefinitely
	if podLogOptions.Follow {
		fakeRuntimeService.Containers[containerID].State = runtimeapi.ContainerState_CONTAINER_EXITED
	}

	opts := logs.NewLogOptions(podLogOptions, time.Now())
	stdoutBuf := bytes.NewBuffer(nil)
	stderrBuf := bytes.NewBuffer(nil)
	_ = logs.ReadLogs(context.TODO(), "/tmp/logfile", containerID, opts, fakeRuntimeService, stdoutBuf, stderrBuf)
	return 1
}
