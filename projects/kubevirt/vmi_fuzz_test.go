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
	"fmt"
	stdruntime "runtime"
	"testing"

	"k8s.io/apimachinery/pkg/util/rand"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/mock/gomock"
	k8sv1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfield "k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/tools/record"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
	kubevirtfake "kubevirt.io/client-go/kubevirt/fake"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"

	"kubevirt.io/client-go/log"

	fakenetworkclient "kubevirt.io/client-go/networkattachmentdefinitionclient/fake"

	kvcontroller "kubevirt.io/kubevirt/pkg/controller"
	"kubevirt.io/kubevirt/pkg/pointer"
	"kubevirt.io/kubevirt/pkg/testutils"
	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"
	"kubevirt.io/kubevirt/pkg/virt-controller/services"
	"kubevirt.io/kubevirt/pkg/virt-controller/watch/topology"
	fuzztestutils "kubevirt.io/kubevirt/pkg/virt-controller/watch/testutils"
	"kubevirt.io/kubevirt/pkg/virt-controller/watch/vmi"
)

var (
	maxResources      = 3
	kvObjectNamespace = "kubevirt"
	kvObjectName      = "kubevirt"
)

func NewFakeClusterConfigUsingKV(kv *virtv1.KubeVirt) (*virtconfig.ClusterConfig, cache.SharedIndexInformer, cache.Store, *framework.FakeControllerSource, *framework.FakeControllerSource) {
	return NewFakeClusterConfigUsingKVWithCPUArch(kv, stdruntime.GOARCH)
}

func NewFakeClusterConfigUsingKVWithCPUArch(kv *virtv1.KubeVirt, CPUArch string) (*virtconfig.ClusterConfig, cache.SharedIndexInformer, cache.Store, *framework.FakeControllerSource, *framework.FakeControllerSource) {
	kv.ResourceVersion = rand.String(10)
	kv.Status.Phase = "Deployed"
	crdInformer, cs1 := testutils.NewFakeInformerFor(&extv1.CustomResourceDefinition{})
	kubeVirtInformer, cs2 := testutils.NewFakeInformerFor(&virtv1.KubeVirt{})

	kubeVirtInformer.GetStore().Add(kv)

	AddDataVolumeAPI(crdInformer)
	cfg, _ := virtconfig.NewClusterConfigWithCPUArch(crdInformer, kubeVirtInformer, kvObjectNamespace, CPUArch)
	return cfg, crdInformer, kubeVirtInformer.GetStore(), cs1, cs2
}

func AddDataVolumeAPI(crdInformer cache.SharedIndexInformer) {
	crdInformer.GetStore().Add(&extv1.CustomResourceDefinition{
		Spec: extv1.CustomResourceDefinitionSpec{
			Names: extv1.CustomResourceDefinitionNames{
				Kind: "DataVolume",
			},
		},
	})
}

func NewFakeClusterConfigUsingKVConfig(kv *virtv1.KubeVirt) (*virtconfig.ClusterConfig, cache.SharedIndexInformer, cache.Store, *framework.FakeControllerSource, *framework.FakeControllerSource) {
	return NewFakeClusterConfigUsingKV(kv)
}

// FuzzExecute add up to 3 virtual machine instances,
// pods, persistent volume claims and data volumes
// to the context and then runs the controller.
func FuzzExecute(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, numberOfVMI, numberOfPods, numberOfPVC, numberOfDataVolumes uint8) {
		currentName := 1
		
		// Create fuzzer with custom functions for valid K8s objects
		cf := gofuzzheaders.NewConsumer(data)
		cf.AddFuncs([]interface{}{
			fuzztestutils.CustomObjectMetaFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMIFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomPodFuzzer(),
			fuzztestutils.CustomPVCFuzzer(),
			fuzztestutils.CustomDataVolumeFuzzer(),
		})
		
		VMIs := make([]*virtv1.VirtualMachineInstance, 0)
		for _ = range int(numberOfVMI) % maxResources {
			vmi := &virtv1.VirtualMachineInstance{}
			cf.GenerateStruct(vmi)
			
			// Ensure name is set (custom fuzzer should handle this, but double-check)
			if vmi.GetObjectMeta().GetName() == "" {
				name := fmt.Sprintf("vmi-%d", currentName)
				currentName += 1
				vmi.Name = name
			}
			if vmi.GetObjectMeta().GetNamespace() == "" {
				vmi.Namespace = k8sv1.NamespaceDefault
			}
			
			vmi.TypeMeta = metav1.TypeMeta{
				Kind:       "VirtualMachineInstance",
				APIVersion: virtv1.SchemeGroupVersion.String(),
			}
			
			// Always set latest API version annotation to pass validation
			kvcontroller.SetLatestApiVersionAnnotation(vmi)
			
			VMIs = append(VMIs, vmi)
		}
		
		pods := make([]*k8sv1.Pod, 0)
		for _ = range int(numberOfPods) % maxResources {
			pod := &k8sv1.Pod{}
			cf.GenerateStruct(pod)
			
			// Ensure valid metadata
			if pod.GetObjectMeta().GetName() == "" {
				pod.Name = fmt.Sprintf("pod-%d", currentName)
				currentName += 1
			}
			if pod.GetObjectMeta().GetNamespace() == "" {
				pod.Namespace = k8sv1.NamespaceDefault
			}
			
			pod.TypeMeta = metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: k8sv1.SchemeGroupVersion.String(),
			}
			pods = append(pods, pod)
		}
		
		PVCs := make([]*k8sv1.PersistentVolumeClaim, 0)
		for _ = range int(numberOfPVC) % maxResources {
			pvc := &k8sv1.PersistentVolumeClaim{}
			cf.GenerateStruct(pvc)
			
			// Ensure valid metadata
			if pvc.GetObjectMeta().GetName() == "" {
				pvc.Name = fmt.Sprintf("pvc-%d", currentName)
				currentName += 1
			}
			if pvc.GetObjectMeta().GetNamespace() == "" {
				pvc.Namespace = k8sv1.NamespaceDefault
			}
			
			pvc.TypeMeta = metav1.TypeMeta{
				Kind:       "PersistentVolumeClaim",
				APIVersion: k8sv1.SchemeGroupVersion.String(),
			}
			PVCs = append(PVCs, pvc)
		}
		
		dataVolumes := make([]*cdiv1.DataVolume, 0)
		for _ = range int(numberOfDataVolumes) % maxResources {
			dataVolume := &cdiv1.DataVolume{}
			cf.GenerateStruct(dataVolume)
			
			// Ensure valid metadata
			if dataVolume.GetObjectMeta().GetName() == "" {
				dataVolume.Name = fmt.Sprintf("dv-%d", currentName)
				currentName += 1
			}
			if dataVolume.GetObjectMeta().GetNamespace() == "" {
				dataVolume.Namespace = k8sv1.NamespaceDefault
			}
			
			dataVolume.TypeMeta = metav1.TypeMeta{
				Kind:       "DataVolume",
				APIVersion: cdiv1.SchemeGroupVersion.String(),
			}
			dataVolumes = append(dataVolumes, dataVolume)
		}
		// There is no point in continuing
		// if we have not created any resources.
		if len(VMIs) == 0 &&
			len(pods) == 0 &&
			len(PVCs) == 0 &&
			len(dataVolumes) == 0 {
			return
		}

		// ignore logs
		var b bytes.Buffer
		log.Log.SetIOWriter(bufio.NewWriter(&b))

		// Create the controller
		kubeClient := fake.NewSimpleClientset()

		virtClient := kubecli.NewMockKubevirtClient(gomock.NewController(t))
		virtClientset := kubevirtfake.NewSimpleClientset()

		vmiInformer, vmiCs := testutils.NewFakeInformerWithIndexersFor(&virtv1.VirtualMachineInstance{}, kvcontroller.GetVMIInformerIndexers())

		vmInformer, vmCs := testutils.NewFakeInformerWithIndexersFor(&virtv1.VirtualMachine{}, kvcontroller.GetVirtualMachineInformerIndexers())
		podInformer, podCs := testutils.NewFakeInformerFor(&k8sv1.Pod{})
		dataVolumeInformer, dataVolumeCs := testutils.NewFakeInformerFor(&cdiv1.DataVolume{})
		storageProfileInformer, storageProfileCs := testutils.NewFakeInformerFor(&cdiv1.StorageProfile{})
		recorder := record.NewFakeRecorder(100)
		recorder.IncludeObject = true

		kv := &virtv1.KubeVirt{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kvObjectName,
				Namespace: kvObjectNamespace,
			},
			Spec: virtv1.KubeVirtSpec{
				Configuration: virtv1.KubeVirtConfiguration{
					DeveloperConfiguration: &virtv1.DeveloperConfiguration{
						MinimumClusterTSCFrequency: pointer.P(int64(12345)),
					},
				},
			},
			Status: virtv1.KubeVirtStatus{
				DefaultArchitecture: stdruntime.GOARCH,
				Phase:               "Deployed",
			},
		}

		config, crdInformer, kubeVirtInformerStore, cs1, cs2 := NewFakeClusterConfigUsingKVConfig(kv)

		// Clean up to avoid excessive memory usage
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

		pvcInformer, pvcCs := testutils.NewFakeInformerFor(&k8sv1.PersistentVolumeClaim{})
		migrationInformer, mCs := testutils.NewFakeInformerFor(&virtv1.VirtualMachineInstanceMigration{})
		storageClassInformer, storageClassCs := testutils.NewFakeInformerFor(&storagev1.StorageClass{})
		cdiInformer, cdiCs := testutils.NewFakeInformerFor(&cdiv1.CDIConfig{})
		cdiConfigInformer, cdiConfigCs := testutils.NewFakeInformerFor(&cdiv1.CDIConfig{})
		rqInformer, rqCs := testutils.NewFakeInformerFor(&k8sv1.ResourceQuota{})
		nsInformer, nsCs := testutils.NewFakeInformerFor(&k8sv1.Namespace{})
		var qemuGid int64 = 107

		stubNetStatusUpdate := func(vmi *virtv1.VirtualMachineInstance, _ *k8sv1.Pod) error {
			vmi.Status.Interfaces = append(vmi.Status.Interfaces, virtv1.VirtualMachineInstanceNetworkInterface{Name: "stubNetStatusUpdate"})
			return nil
		}

		// Clean up controller sources to avoid excessive memory usage
		defer cdiCs.Shutdown()
		defer mCs.Shutdown()
		defer podCs.Shutdown()
		defer dataVolumeCs.Shutdown()
		defer storageProfileCs.Shutdown()
		defer pvcCs.Shutdown()
		defer storageClassCs.Shutdown()
		defer cdiConfigCs.Shutdown()
		defer rqCs.Shutdown()
		defer nsCs.Shutdown()
		defer vmiCs.Shutdown()
		defer vmCs.Shutdown()

		for _, vmi := range VMIs {
			// index and queue or create:
			var indexAndQueue bool
			cf.GenerateStruct(&indexAndQueue)
			if indexAndQueue {
				err := vmiInformer.GetIndexer().Add(vmi)
				if err != nil {
					return
				}
			} else {
				_, err := virtClientset.KubevirtV1().VirtualMachineInstances(vmi.Namespace).Create(context.Background(), vmi, metav1.CreateOptions{})
				if err != nil {
					return
				}
				virtClient.EXPECT().VirtualMachineInstance(vmi.ObjectMeta.Namespace).Return(
					virtClientset.KubevirtV1().VirtualMachineInstances(vmi.ObjectMeta.Namespace),
				).AnyTimes()
			}
		}
		for _, pod := range pods {
			// index and queue or create:
			var indexAndQueue bool
			cf.GenerateStruct(&indexAndQueue)
			if indexAndQueue {
				err := podInformer.GetIndexer().Add(pod)
				if err != nil {
					return
				}
			} else {
				_, err := kubeClient.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{})
				if err != nil {
					return
				}
			}
		}
		for _, pvc := range PVCs {
			// index and queue or create:
			var indexAndQueue bool
			cf.GenerateStruct(&indexAndQueue)
			if indexAndQueue {
				err := pvcInformer.GetIndexer().Add(pvc)
				if err != nil {
					return
				}
			} else {
				_, err := kubeClient.CoreV1().PersistentVolumeClaims(pvc.Namespace).Create(context.Background(), pvc, metav1.CreateOptions{})
				if err != nil {
					return
				}
			}
		}
		for _, dataVolume := range dataVolumes {
			err := dataVolumeInformer.GetIndexer().Add(dataVolume)
			if err != nil {
				return
			}
		}

		controller, err := vmi.NewController(
			services.NewTemplateService("a", 240, "b", "c", "d", "e", "f", pvcInformer.GetStore(), virtClient, config, qemuGid, "g", rqInformer.GetStore(), nsInformer.GetStore()),
			vmiInformer,
			vmInformer,
			podInformer,
			pvcInformer,
			migrationInformer,
			storageClassInformer,
			recorder,
			virtClient,
			dataVolumeInformer,
			storageProfileInformer,
			cdiInformer,
			cdiConfigInformer,
			config,
			topology.NewTopologyHinter(&cache.FakeCustomStore{}, &cache.FakeCustomStore{}, config),
			stubNetworkAnnotationsGenerator{},
			stubNetStatusUpdate,
			validateNetVMISpecStub(),
			stubMigrationEvaluator{result: k8sv1.ConditionUnknown},
			[]string{},
			[]string{},
		)
		if err != nil {
			// We want to know if this happens
			// If the fuzzer fails here, we should
			// explore it, as it might not run
			// correctly.
			panic(err)
		}

		// Shut down the default queue to avoid excessive memory usage.
		defer controller.Queue.ShutDown()
		// Wrap our workqueue to have a way to detect when we are done processing updates
		mockQueue := testutils.NewMockWorkQueue(controller.Queue)
		controller.Queue = mockQueue

		// Set up mock client
		virtClient.EXPECT().CoreV1().Return(kubeClient.CoreV1()).AnyTimes()
		networkClient := fakenetworkclient.NewSimpleClientset()
		virtClient.EXPECT().NetworkClient().Return(networkClient).AnyTimes()

		// Add the resources to the context
		for _, vmi := range VMIs {
			// index and queue or create:
			var indexAndQueue bool
			cf.GenerateStruct(&indexAndQueue)
			if indexAndQueue {
				key, err := kvcontroller.KeyFunc(vmi)
				if err != nil {
					return
				}
				controller.Queue.Add(key)

			} else {
				_, err = virtClientset.KubevirtV1().VirtualMachineInstances(vmi.Namespace).Create(context.Background(), vmi, metav1.CreateOptions{})
				if err != nil {
					return
				}
			}
			virtClient.EXPECT().VirtualMachineInstance(vmi.ObjectMeta.Namespace).Return(
				virtClientset.KubevirtV1().VirtualMachineInstances(vmi.ObjectMeta.Namespace),
			).AnyTimes()
		}
		for _, pod := range pods {
			// index and queue or create:
			var indexAndQueue bool
			cf.GenerateStruct(&indexAndQueue)
			if indexAndQueue {
				key, err := kvcontroller.KeyFunc(pod)
				if err != nil {
					return
				}
				controller.Queue.Add(key)
			} else {
				_, err = kubeClient.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{})
				if err != nil {
					return
				}
			}
		}
		for _, pvc := range PVCs {
			// index and queue or create:
			var indexAndQueue bool
			cf.GenerateStruct(&indexAndQueue)
			if indexAndQueue {
				key, err := kvcontroller.KeyFunc(pvc)
				if err != nil {
					return
				}
				controller.Queue.Add(key)
			} else {
				_, err = kubeClient.CoreV1().PersistentVolumeClaims(pvc.Namespace).Create(context.Background(), pvc, metav1.CreateOptions{})
				if err != nil {
					return
				}
			}
		}
		for _, dataVolume := range dataVolumes {
			key, err := kvcontroller.KeyFunc(dataVolume)
			if err != nil {
				return
			}
			controller.Queue.Add(key)
		}
		if controller.Queue.Len() == 0 {
			return
		}

		// Run the controller
		for i := controller.Queue.Len(); i > 0; i-- {
			controller.Execute()
		}

	})
}

func validateNetVMISpecStub(causes ...metav1.StatusCause) func(*k8sfield.Path, *virtv1.VirtualMachineInstanceSpec, *virtconfig.ClusterConfig) []metav1.StatusCause {
	return func(*k8sfield.Path, *virtv1.VirtualMachineInstanceSpec, *virtconfig.ClusterConfig) []metav1.StatusCause {
		return causes
	}
}

type stubNetworkAnnotationsGenerator struct {
	annotations map[string]string
}

func (s stubNetworkAnnotationsGenerator) GenerateFromActivePod(_ *virtv1.VirtualMachineInstance, _ *k8sv1.Pod) map[string]string {
	return s.annotations
}

type stubMigrationEvaluator struct {
	result k8sv1.ConditionStatus
}

func (e stubMigrationEvaluator) Evaluate(_ *virtv1.VirtualMachineInstance) k8sv1.ConditionStatus {
	return e.result
}
