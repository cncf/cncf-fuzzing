// Copyright 2025 the cncf-fuzzing authors
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

package fuzz

import (
	"bufio"
	"bytes"
	"context"
	"reflect"
	"testing"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/mock/gomock"
	k8sv1 "k8s.io/api/core/v1"
	resourcev1beta1 "k8s.io/api/resource/v1beta1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
	kubevirtfake "kubevirt.io/client-go/kubevirt/fake"
	"kubevirt.io/client-go/log"

	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"

	virtcontroller "kubevirt.io/kubevirt/pkg/controller"
	"kubevirt.io/kubevirt/pkg/testutils"
	"kubevirt.io/kubevirt/pkg/virt-controller/watch/dra"
	fuzztestutils "kubevirt.io/kubevirt/pkg/virt-controller/watch/testutils"
)

var (
	maxResources      = 3
	kvObjectNamespace = "kubevirt"
	kvObjectName      = "kubevirt"
)

func NewFakeClusterConfigUsingKVWithDRA(kv *v1.KubeVirt) (*virtconfig.ClusterConfig, cache.SharedIndexInformer, cache.SharedIndexInformer, cache.Store, *framework.FakeControllerSource, *framework.FakeControllerSource) {
	kv.ResourceVersion = rand.String(10)
	kv.Status.Phase = "Deployed"
	crdInformer, cs1 := testutils.NewFakeInformerFor(&extv1.CustomResourceDefinition{})
	kubeVirtInformer, cs2 := testutils.NewFakeInformerFor(&v1.KubeVirt{})

	kubeVirtInformer.GetStore().Add(kv)

	cfg, _ := virtconfig.NewClusterConfig(crdInformer, kubeVirtInformer, kvObjectNamespace)
	return cfg, crdInformer, kubeVirtInformer, kubeVirtInformer.GetStore(), cs1, cs2
}

// FuzzExecute fuzzes the DRA Status Controller Execute method
func FuzzExecute(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte,
		numberOfVMIs,
		numberOfPods,
		numberOfResourceClaims,
		numberOfResourceSlices uint8) {

		// Create fuzzer with custom functions for valid K8s objects
		cf := gofuzzheaders.NewConsumer(data)
		cf.AddFuncs([]interface{}{
			fuzztestutils.CustomObjectMetaFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMIFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomPodFuzzer(),
		})

		vmis := make([]*v1.VirtualMachineInstance, 0)
		for _ = range int(numberOfVMIs) % maxResources {
			vmi := &v1.VirtualMachineInstance{}
			cf.GenerateStruct(vmi)

			// Ensure metadata is set
			if vmi.Name == "" {
				vmi.Name = "vmi-" + rand.String(5)
			}
			if vmi.Namespace == "" {
				vmi.Namespace = k8sv1.NamespaceDefault
			}

			// Add some GPU/host device configuration
			var addGPU, addHostDevice bool
			cf.GenerateStruct(&addGPU)
			cf.GenerateStruct(&addHostDevice)

			if addGPU {
				if vmi.Spec.Domain.Devices.GPUs == nil {
					vmi.Spec.Domain.Devices.GPUs = []v1.GPU{}
				}
				gpu := v1.GPU{
					Name:       "gpu-" + rand.String(3),
					DeviceName: "nvidia.com/gpu",
				}
				vmi.Spec.Domain.Devices.GPUs = append(vmi.Spec.Domain.Devices.GPUs, gpu)
			}

			if addHostDevice {
				if vmi.Spec.Domain.Devices.HostDevices == nil {
					vmi.Spec.Domain.Devices.HostDevices = []v1.HostDevice{}
				}
				hostDevice := v1.HostDevice{
					Name:       "hostdev-" + rand.String(3),
					DeviceName: "vendor.com/device",
				}
				vmi.Spec.Domain.Devices.HostDevices = append(vmi.Spec.Domain.Devices.HostDevices, hostDevice)
			}

			vmis = append(vmis, vmi)
		}

		pods := make([]*k8sv1.Pod, 0)
		for i := range int(numberOfPods) % maxResources {
			pod := &k8sv1.Pod{}
			cf.GenerateStruct(pod)

			// Ensure metadata
			if pod.Name == "" {
				pod.Name = "virt-launcher-" + rand.String(5)
			}
			if pod.Namespace == "" {
				pod.Namespace = k8sv1.NamespaceDefault
			}

			// Link to VMI if available
			if i < len(vmis) {
				if pod.Labels == nil {
					pod.Labels = make(map[string]string)
				}
				// Use kubevirt.io domain label for VMI association
				pod.Labels["kubevirt.io/vm"] = vmis[i].Name
			}

			pods = append(pods, pod)
		}

		resourceClaims := make([]*resourcev1beta1.ResourceClaim, 0)
		for _ = range int(numberOfResourceClaims) % maxResources {
			claim := &resourcev1beta1.ResourceClaim{}
			cf.GenerateStruct(claim)

			// Ensure metadata
			if claim.Name == "" {
				claim.Name = "claim-" + rand.String(5)
			}
			if claim.Namespace == "" {
				claim.Namespace = k8sv1.NamespaceDefault
			}

			resourceClaims = append(resourceClaims, claim)
		}

		resourceSlices := make([]*resourcev1beta1.ResourceSlice, 0)
		for _ = range int(numberOfResourceSlices) % maxResources {
			slice := &resourcev1beta1.ResourceSlice{}
			cf.GenerateStruct(slice)

			// Ensure metadata (ResourceSlice is cluster-scoped)
			if slice.Name == "" {
				slice.Name = "slice-" + rand.String(5)
			}

			resourceSlices = append(resourceSlices, slice)
		}

		// ignore logs
		var b bytes.Buffer
		log.Log.SetIOWriter(bufio.NewWriter(&b))

		virtClient := kubecli.NewMockKubevirtClient(gomock.NewController(t))
		virtClientset := kubevirtfake.NewSimpleClientset()

		vmiInformer, vmiCs := testutils.NewFakeInformerFor(&v1.VirtualMachineInstance{})
		podInformer, podCs := testutils.NewFakeInformerFor(&k8sv1.Pod{})
		resourceClaimInformer, rcCs := testutils.NewFakeInformerFor(&resourcev1beta1.ResourceClaim{})
		resourceSliceInformer, rsCs := testutils.NewFakeInformerFor(&resourcev1beta1.ResourceSlice{})
		defer vmiCs.Shutdown()
		defer podCs.Shutdown()
		defer rcCs.Shutdown()
		defer rsCs.Shutdown()

		recorder := record.NewFakeRecorder(100)
		recorder.IncludeObject = true

		// Create KubeVirt CR with DRA gates enabled
		kv := &v1.KubeVirt{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kvObjectName,
				Namespace: kvObjectNamespace,
			},
			Spec: v1.KubeVirtSpec{
				Configuration: v1.KubeVirtConfiguration{
					DeveloperConfiguration: &v1.DeveloperConfiguration{
						FeatureGates: []string{"DRAWithGPUs", "DRAWithHostDevices"},
					},
				},
			},
			Status: v1.KubeVirtStatus{
				Phase: "Deployed",
			},
		}

		config, crdInformer, _, kubeVirtInformerStore, cs1, cs2 := NewFakeClusterConfigUsingKVWithDRA(kv)
		defer cs1.Shutdown()
		defer cs2.Shutdown()
		defer kubeVirtInformerStore.Delete(kv)
		defer func() {
			for _, obj := range crdInformer.GetStore().List() {
				err := crdInformer.GetStore().Delete(obj)
				if err != nil {
					panic(err)
				}
			}
		}()

		controller, err := dra.NewDRAStatusController(
			config,
			vmiInformer,
			podInformer,
			resourceClaimInformer,
			resourceSliceInformer,
			recorder,
			virtClient,
		)
		if err != nil {
			return
		}

		// Access private queue field using reflection
		controllerValue := reflect.ValueOf(controller).Elem()
		queueField := controllerValue.FieldByName("queue")
		if !queueField.IsValid() {
			return
		}
		
		// Get the queue interface
		queue := queueField.Interface().(workqueue.TypedRateLimitingInterface[string])
		
		// Wrap our workqueue to have a way to detect when we are done processing updates
		mockQueue := testutils.NewMockWorkQueue(queue)
		queue.ShutDown()
		
		// Set the mock queue back using reflection
		queueField.Set(reflect.ValueOf(mockQueue))

		// Set up mock client
		kubeClient := fake.NewSimpleClientset()
		virtClient.EXPECT().VirtualMachineInstance(k8sv1.NamespaceDefault).Return(virtClientset.KubevirtV1().VirtualMachineInstances(k8sv1.NamespaceDefault)).AnyTimes()
		virtClient.EXPECT().CoreV1().Return(kubeClient.CoreV1()).AnyTimes()

		// Add the resources to the stores and queue
		for _, vmi := range vmis {
			if len(vmi.Annotations) == 0 {
				vmi.Annotations = nil
			}
			if len(vmi.Labels) == 0 {
				vmi.Labels = nil
			}

			var addToQueue bool
			var create bool
			cf.GenerateStruct(&addToQueue)
			cf.GenerateStruct(&create)

			if addToQueue {
				vmiInformer.GetStore().Add(vmi)
				key, err := virtcontroller.KeyFunc(vmi)
				if err != nil {
					return
				}
				mockQueue.Add(key)
			}
			if create {
				virtClientset.KubevirtV1().VirtualMachineInstances(vmi.Namespace).Create(context.Background(), vmi, metav1.CreateOptions{})
			}
		}

		for _, pod := range pods {
			var addToStore bool
			cf.GenerateStruct(&addToStore)

			if addToStore {
				err := podInformer.GetIndexer().Add(pod)
				if err != nil {
					return
				}
			}
		}

		for _, claim := range resourceClaims {
			var addToStore bool
			cf.GenerateStruct(&addToStore)

			if addToStore {
				err := resourceClaimInformer.GetStore().Add(claim)
				if err != nil {
					return
				}
			}
		}

		for _, slice := range resourceSlices {
			var addToStore bool
			cf.GenerateStruct(&addToStore)

			if addToStore {
				err := resourceSliceInformer.GetIndexer().Add(slice)
				if err != nil {
					return
				}
			}
		}

		if mockQueue.Len() == 0 {
			return
		}

		// Run the controller Execute method
		controller.Execute()
	})
}
