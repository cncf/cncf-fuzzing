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
	stdruntime "runtime"
	"testing"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	k8sv1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes/fake"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/tools/record"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	virtController "kubevirt.io/kubevirt/pkg/controller"
	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"
	"kubevirt.io/kubevirt/pkg/virt-controller/watch/drain/disruptionbudget"
	fuzztestutils "kubevirt.io/kubevirt/pkg/virt-controller/watch/testutils"

	"kubevirt.io/kubevirt/pkg/testutils"
)

var (
	maxResources      = 3
	kvObjectNamespace = "kubevirt"
	kvObjectName      = "kubevirt"
)

func NewFakeClusterConfigUsingKV(kv *v1.KubeVirt) (*virtconfig.ClusterConfig, cache.SharedIndexInformer, cache.Store, *framework.FakeControllerSource, *framework.FakeControllerSource) {
	return NewFakeClusterConfigUsingKVWithCPUArch(kv, stdruntime.GOARCH)
}

func NewFakeClusterConfigUsingKVWithCPUArch(kv *v1.KubeVirt, CPUArch string) (*virtconfig.ClusterConfig, cache.SharedIndexInformer, cache.Store, *framework.FakeControllerSource, *framework.FakeControllerSource) {
	kv.ResourceVersion = rand.String(10)
	kv.Status.Phase = "Deployed"
	crdInformer, cs1 := testutils.NewFakeInformerFor(&extv1.CustomResourceDefinition{})
	kubeVirtInformer, cs2 := testutils.NewFakeInformerFor(&v1.KubeVirt{})

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

func NewFakeClusterConfigUsingKVConfig(kv *v1.KubeVirt) (*virtconfig.ClusterConfig, cache.SharedIndexInformer, cache.Store, *framework.FakeControllerSource, *framework.FakeControllerSource) {
	return NewFakeClusterConfigUsingKV(kv)
}

// FuzzExecute add up to 3 resources
// to the context and then runs the controller.
func FuzzExecute(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte,
		numberOfVMIs,
		numberOfVMIMigrations,
		numberOfPods,
		numberOfPDBs uint8) {
		
		// Create go-fuzz-headers consumer with custom functions
		cf := gofuzzheaders.NewConsumer(data)
		cf.AddFuncs([]interface{}{
			fuzztestutils.CustomObjectMetaFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMIFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomPodFuzzer(),
			fuzztestutils.CustomPodDisruptionBudgetFuzzer(),
			fuzztestutils.CustomVMIMigrationFuzzer(k8sv1.NamespaceDefault),
		})

		vmis := make([]*v1.VirtualMachineInstance, 0)
		for _ = range int(numberOfVMIs) % maxResources {
			vmi := &v1.VirtualMachineInstance{}
			if err := cf.GenerateStruct(vmi); err != nil {
				continue
			}
			vmis = append(vmis, vmi)
		}

		pods := make([]*k8sv1.Pod, 0)
		for _ = range int(numberOfPods) % maxResources {
			pod := &k8sv1.Pod{}
			if err := cf.GenerateStruct(pod); err != nil {
				continue
			}
			pods = append(pods, pod)
		}

		vmiMigrations := make([]*v1.VirtualMachineInstanceMigration, 0)
		for _ = range int(numberOfVMIMigrations) % maxResources {
			vmiMigration := &v1.VirtualMachineInstanceMigration{}
			if err := cf.GenerateStruct(vmiMigration); err != nil {
				continue
			}
			vmiMigrations = append(vmiMigrations, vmiMigration)
		}

		pdbs := make([]*policyv1.PodDisruptionBudget, 0)
		for _ = range int(numberOfPDBs) % maxResources {
			pdb := &policyv1.PodDisruptionBudget{}
			if err := cf.GenerateStruct(pdb); err != nil {
				continue
			}
			pdbs = append(pdbs, pdb)
		}
		if len(vmis)+len(pods)+len(vmiMigrations)+len(pdbs) < 3 {
			return
		}

		ctrl := gomock.NewController(t)
		virtClient := kubecli.NewMockKubevirtClient(ctrl)
		vmiInformer, vmiSource := testutils.NewFakeInformerFor(&v1.VirtualMachineInstance{})
		pdbInformer, pdbSource := testutils.NewFakeInformerFor(&policyv1.PodDisruptionBudget{})
		vmimInformer, vmimSource := testutils.NewFakeInformerFor(&v1.VirtualMachineInstanceMigration{})
		podInformer, podSource := testutils.NewFakeInformerFor(&corev1.Pod{})
		recorder := record.NewFakeRecorder(100)
		recorder.IncludeObject = true

		defer vmiSource.Shutdown()
		defer pdbSource.Shutdown()
		defer vmimSource.Shutdown()
		defer podSource.Shutdown()

		controller, _ := disruptionbudget.NewDisruptionBudgetController(vmiInformer,
			pdbInformer,
			podInformer,
			vmimInformer,
			recorder,
			virtClient)
		// Shut down default controller queue to avoid memory leak
		controller.Queue.ShutDown()
		mockQueue := testutils.NewMockWorkQueue(controller.Queue)
		controller.Queue = mockQueue

		// Set up mock client
		kubeClient := fake.NewSimpleClientset()
		virtClient.EXPECT().CoreV1().Return(kubeClient.CoreV1()).AnyTimes()
		virtClient.EXPECT().PolicyV1().Return(kubeClient.PolicyV1()).AnyTimes()

		// Make sure that all unexpected calls to kubeClient will fail
		kubeClient.Fake.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, obj runtime.Object, err error) {
			return true, nil, nil
		})

		// Add the resources to the context
		for _, vmi := range vmis {
			key, err := virtController.KeyFunc(vmi)
			if err != nil {
				continue
			}
			controller.Queue.Add(key)
			vmiSource.Add(vmi)
		}
		for _, vmiMigration := range vmiMigrations {
			err := vmimInformer.GetIndexer().Add(vmiMigration)
			if err != nil {
				return
			}
		}
		for _, pod := range pods {
			err := podInformer.GetIndexer().Add(pod)
			if err != nil {
				return
			}
		}
		for _, pdb := range pdbs {
			key, err := virtController.KeyFunc(pdb)
			if err != nil {
				continue
			}
			controller.Queue.Add(key)
			pdbSource.Add(pdb)
		}
		if controller.Queue.Len() == 0 {
			return
		}

		// Run the controller
		controller.Execute()
	})
}
