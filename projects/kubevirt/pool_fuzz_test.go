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
	"fmt"
	"testing"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/mock/gomock"
	appsv1 "k8s.io/api/apps/v1"
	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	v1 "kubevirt.io/api/core/v1"
	poolv1 "kubevirt.io/api/pool/v1beta1"
	"kubevirt.io/client-go/kubecli"
	kubevirtfake "kubevirt.io/client-go/kubevirt/fake"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"

	virtcontroller "kubevirt.io/kubevirt/pkg/controller"
	"kubevirt.io/kubevirt/pkg/testutils"
	"kubevirt.io/kubevirt/pkg/virt-controller/watch/pool"
	fuzztestutils "kubevirt.io/kubevirt/pkg/virt-controller/watch/testutils"
)

var (
	maxResources = 3
)

// FuzzExecute adds random resources to the context
// and then runs the controller.
func FuzzExecute(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, numberOfCRs, numberOfVMs uint8) {
		// Create go-fuzz-headers consumer with custom functions
		cf := gofuzzheaders.NewConsumer(data)
		cf.AddFuncs([]interface{}{
			fuzztestutils.CustomObjectMetaFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMIFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMPoolFuzzer(k8sv1.NamespaceDefault),
		})

		crs := make([]*appsv1.ControllerRevision, 0)
		for _ = range int(numberOfCRs) % maxResources {
			cr := &appsv1.ControllerRevision{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("cr-%d", len(crs)),
					Namespace: k8sv1.NamespaceDefault,
				},
				Revision: int64(1 + len(crs)),
			}
			crs = append(crs, cr)
		}

		vms := make([]*v1.VirtualMachine, 0)
		for _ = range int(numberOfVMs) % maxResources {
			vm := &v1.VirtualMachine{}
			if err := cf.GenerateStruct(vm); err != nil {
				continue
			}
			if vm != nil {
				vms = append(vms, vm)
			}

			vmis := make([]*v1.VirtualMachineInstance, 0)
			for _ = range int(numberOfVMs) % maxResources {
				vmi := &v1.VirtualMachineInstance{}
				if err := cf.GenerateStruct(vmi); err != nil {
					continue
				}
				if vmi != nil {
					vmis = append(vmis, vmi)
				}
			}

			vmPools := make([]*poolv1.VirtualMachinePool, 0)
			for _ = range int(numberOfVMs) % maxResources {
				vmPool := &poolv1.VirtualMachinePool{}
				if err := cf.GenerateStruct(vmPool); err != nil {
					continue
				}
				if vmPool != nil {
					vmPools = append(vmPools, vmPool)
				}
			}
			// There is no point in continuing
			// if we have not created any resources.
			if len(vms)+len(vms)+len(vmis)+len(vmPools) < 3 {
				return
			}

			virtClient := kubecli.NewMockKubevirtClient(gomock.NewController(t))

			vmiInformer, _ := testutils.NewFakeInformerFor(&v1.VirtualMachineInstance{})
			vmInformer, _ := testutils.NewFakeInformerFor(&v1.VirtualMachine{})
			poolInformer, _ := testutils.NewFakeInformerFor(&poolv1.VirtualMachinePool{})
			pvcInformer, _ := testutils.NewFakeInformerFor(&k8sv1.PersistentVolumeClaim{})
			dvInformer, _ := testutils.NewFakeInformerFor(&cdiv1.DataVolume{})
			recorder := record.NewFakeRecorder(100)
			recorder.IncludeObject = true

			crInformer, _ := testutils.NewFakeInformerWithIndexersFor(&appsv1.ControllerRevision{}, cache.Indexers{
				"vmpool": func(obj interface{}) ([]string, error) {
					cr := obj.(*appsv1.ControllerRevision)
					for _, ref := range cr.OwnerReferences {
						if ref.Kind == "VirtualMachinePool" {
							return []string{string(ref.UID)}, nil
						}
					}
					return nil, nil
				},
			})

			controller, _ := pool.NewController(virtClient,
				vmiInformer,
				vmInformer,
				poolInformer,
				pvcInformer,
				dvInformer,
				crInformer,
				recorder,
				uint(10))
			fakeVirtClient := kubevirtfake.NewSimpleClientset()
			mockQueue := testutils.NewMockWorkQueue(pool.GetQueue(controller))
			// Add the resources to the context
			for _, cr := range crs {
				if cr == nil {
					continue
				}
				crInformer.GetIndexer().Add(cr)
				key, err := virtcontroller.KeyFunc(cr)
				if err != nil {
					return
				}
				mockQueue.Add(key)
			}
			for _, vm := range vms {
				if vm == nil {
					continue
				}
				vmInformer.GetIndexer().Add(vm)
				key, err := virtcontroller.KeyFunc(vm)
				if err != nil {
					return
				}
				mockQueue.Add(key)
			}
			for _, vmi := range vmis {
				if vmi == nil {
					continue
				}
				vmiInformer.GetStore().Add(vmi)
				key, err := virtcontroller.KeyFunc(vmi)
				if err != nil {
					return
				}
				mockQueue.Add(key)
			}
			for _, vmPool := range vmPools {
				if vmPool == nil {
					continue
				}
				poolInformer.GetIndexer().Add(vmPool)
				key, err := virtcontroller.KeyFunc(vmPool)
				if err != nil {
					return
				}
				mockQueue.Add(key)
				// Don't mock VirtualMachinePool - it causes type mismatch errors
				// The controller will work with objects from the informer store

			}
			if mockQueue.Len() == 0 {
				return
			}
			pool.ShutdownCtrlQueue(controller)
			pool.SetQueue(controller, mockQueue)

			// Set up mock client
			virtClient.EXPECT().VirtualMachineInstance(gomock.Any()).Return(fakeVirtClient.KubevirtV1().VirtualMachineInstances(metav1.NamespaceDefault)).AnyTimes()
			virtClient.EXPECT().VirtualMachine(gomock.Any()).Return(fakeVirtClient.KubevirtV1().VirtualMachines(metav1.NamespaceDefault)).AnyTimes()
			virtClient.EXPECT().VirtualMachinePool(gomock.Any()).Return(fakeVirtClient.PoolV1beta1().VirtualMachinePools(metav1.NamespaceDefault)).AnyTimes()
			fakeVirtClient.Fake.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, obj runtime.Object, err error) {
				return true, nil, nil
			})

			k8sClient := k8sfake.NewSimpleClientset()
			k8sClient.Fake.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, obj runtime.Object, err error) {
				return true, nil, nil
			})
			virtClient.EXPECT().AppsV1().Return(k8sClient.AppsV1()).AnyTimes()

			// Run the controller
			controller.Execute()
		}
	})
}
