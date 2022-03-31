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

package kubelet

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	containertest "k8s.io/kubernetes/pkg/kubelet/container/testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func init() {
	testing.Init()
}

func FuzzSyncPod(data []byte) int {
	syncTypes := []kubetypes.SyncPodType{kubetypes.SyncPodCreate,
		kubetypes.SyncPodUpdate,
		kubetypes.SyncPodSync,
		kubetypes.SyncPodKill}
	t := &testing.T{}
	f := fuzz.NewConsumer(data)
	pod2 := &v1.Pod{}
	err := f.GenerateStruct(pod2)
	if err != nil {
		return 0
	}
	syncTypeIndex, err := f.GetInt()
	if err != nil {
		return 0
	}
	syncType := syncTypes[syncTypeIndex%len(syncTypes)]
	testKubelet := newTestKubelet(t, false)
	defer testKubelet.Cleanup()
	kl := testKubelet.kubelet
	/*manager := testKubelet.fakeMirrorClient
	  _ = manager*/
	pod := podWithUIDNameNs("12345678", "bar", "foo")
	pod.Annotations[kubetypes.ConfigSourceAnnotationKey] = "file"
	pods := []*v1.Pod{pod, pod2}
	kl.podManager.SetPods(pods)
	_, _ = kl.syncPod(context.Background(), syncType, pod, nil, &kubecontainer.PodStatus{})
	return 1
}

func FuzzStrategicMergePatch(data []byte) int {
	if len(data) < 10 {
		return 0
	}
	if (len(data) % 2) != 0 {
		return 0
	}
	original := data[:len(data)/2]
	patch := data[(len(data)/2)+1:]
	_, _ = strategicpatch.StrategicMergePatch(original, patch, v1.Node{})
	return 1
}

func FuzzconvertToAPIContainerStatuses(data []byte) int {
	t := &testing.T{}
	f := fuzz.NewConsumer(data)
	pod := &v1.Pod{}
	err := f.GenerateStruct(pod)
	if err != nil {
		return 0
	}

	currentStatus := &kubecontainer.PodStatus{} // leave empty at first
	err = f.GenerateStruct(currentStatus)
	if err != nil {
		return 0
	}

	previousStatus, err := createContainerStatuses(f)
	if err != nil {
		return 0
	}

	containers, err := createContainers(f)
	if err != nil {
		return 0
	}

	hasInitContainers, err := f.GetBool()
	if err != nil {
		return 0
	}

	isInitContainer, err := f.GetBool()
	if err != nil {
		return 0
	}

	testKubelet := newTestKubelet(t, false)
	defer testKubelet.Cleanup()
	kl := testKubelet.kubelet

	_ = kl.convertToAPIContainerStatuses(pod, currentStatus, previousStatus, containers, hasInitContainers, isInitContainer)
	return 1
}

func createContainers(f *fuzz.ConsumeFuzzer) ([]v1.Container, error) {
	containers := make([]v1.Container, 0)
	noOfContainers, err := f.GetInt()
	if err != nil {
		return containers, err
	}
	for i := 0; i < noOfContainers%30; i++ {
		c := v1.Container{}
		err := f.GenerateStruct(&c)
		if err != nil {
			return containers, err
		}
		containers = append(containers, c)
	}
	return containers, nil
}

func createContainerStatuses(f *fuzz.ConsumeFuzzer) ([]v1.ContainerStatus, error) {
	containerStatuses := make([]v1.ContainerStatus, 0)
	noOfContainerStatuses, err := f.GetInt()
	if err != nil {
		return containerStatuses, err
	}
	for i := 0; i < noOfContainerStatuses%30; i++ {
		c := v1.ContainerStatus{}
		err := f.GenerateStruct(&c)
		if err != nil {
			return containerStatuses, err
		}
		containerStatuses = append(containerStatuses, c)
	}
	return containerStatuses, nil
}

func FuzzHandlePodCleanups(data []byte) int {
	t := &testing.T{}
	f := fuzz.NewConsumer(data)
	pod := &kubecontainer.Pod{}
	err := f.GenerateStruct(pod)
	if err != nil {
		return 0
	}
	podID := pod.ID

	testKubelet := newTestKubelet(t, false /* controllerAttachDetachEnabled */)
	defer testKubelet.Cleanup()

	fakeRuntime := testKubelet.fakeRuntime
	fakeContainerManager := testKubelet.fakeContainerManager
	fakeContainerManager.PodContainerManager.AddPodFromCgroups(pod) // add pod to mock cgroup
	fakeRuntime.PodList = []*containertest.FakePod{
		{Pod: pod},
	}
	kubelet := testKubelet.kubelet
	kubelet.cgroupsPerQOS = true

	kubelet.HandlePodCleanups()
	if actual, expected := kubelet.podWorkers.(*fakePodWorkers).triggeredDeletion, []types.UID{podID}; !reflect.DeepEqual(actual, expected) {
		panic(fmt.Sprintf("expected %v to be deleted, got %v\n", expected, actual))
	}
	fakeRuntime.AssertKilledPods([]string(nil))

	return 1
}

func FuzzMakeEnvironmentVariables(data []byte) int {
	t := &testing.T{}
	f := fuzz.NewConsumer(data)
	testPod := &v1.Pod{}
	err := f.GenerateStruct(testPod)
	if err != nil {
		return 0
	}
	container := &v1.Container{}
	err = f.GenerateStruct(container)
	if err != nil {
		return 0
	}
	podIP, err := f.GetString()
	if err != nil {
		return 0
	}
	podIPs := make([]string, 0)
	err = f.CreateSlice(&podIPs)
	if err != nil {
		return 0
	}
	kl := newTestKubelet(t, false /* controllerAttachDetachEnabled */)
	defer kl.Cleanup()
	_, _ = kl.kubelet.makeEnvironmentVariables(testPod, container, podIP, podIPs)
	return 1
}