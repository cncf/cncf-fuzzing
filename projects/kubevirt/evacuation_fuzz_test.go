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
	k8sv1 "k8s.io/api/core/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes/fake"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/tools/record"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
	kubevirtfake "kubevirt.io/client-go/kubevirt/fake"

	virtController "kubevirt.io/kubevirt/pkg/controller"
	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"
	"kubevirt.io/kubevirt/pkg/virt-controller/watch/drain/evacuation"
	fuzztestutils "kubevirt.io/kubevirt/pkg/virt-controller/watch/testutils"

	"kubevirt.io/kubevirt/pkg/testutils"
)

var (
	maxResources      = 4
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

// FuzzExecute random resources to the context
// and then runs the controller.
func FuzzExecute(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte,
		numberOfVMIs,
		numberOfNodes,
		numberOfPods,
		numberOfMigrations uint8) {
		
		// Create fuzzer with custom functions for valid K8s objects
		cf := gofuzzheaders.NewConsumer(data)
		cf.AddFuncs([]interface{}{
			fuzztestutils.CustomObjectMetaFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMIFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomNodeWithTaintsFuzzer(),
			fuzztestutils.CustomPodFuzzer(),
			fuzztestutils.CustomVMIMigrationFuzzer(k8sv1.NamespaceDefault),
		})

		vmis := make([]*v1.VirtualMachineInstance, 0)
		for _ = range int(numberOfVMIs) % maxResources {
			vmi := &v1.VirtualMachineInstance{}
			cf.GenerateStruct(vmi)
			
			if vmi.Name == "" {
				vmi.Name = "vmi-" + rand.String(5)
			}
			if vmi.Namespace == "" {
				vmi.Namespace = k8sv1.NamespaceDefault
			}
			vmis = append(vmis, vmi)
		}

		nodes := make([]*k8sv1.Node, 0)
		for _ = range int(numberOfNodes) % maxResources {
			node := &k8sv1.Node{}
			cf.GenerateStruct(node)
			nodes = append(nodes, node)
		}
		
		// Assign VMIs to nodes
		for i, vmi := range vmis {
			if len(nodes) > 0 && vmi.Status.NodeName == "" {
				vmi.Status.NodeName = nodes[i%len(nodes)].Name
			}
		}

		pods := make([]*k8sv1.Pod, 0)
		for _ = range int(numberOfPods) % maxResources {
			pod := &k8sv1.Pod{}
			cf.GenerateStruct(pod)
			
			if pod.Name == "" {
				pod.Name = "pod-" + rand.String(5)
			}
			if pod.Namespace == "" {
				pod.Namespace = k8sv1.NamespaceDefault
			}
			pods = append(pods, pod)
		}

		migrations := make([]*v1.VirtualMachineInstanceMigration, 0)
		for _ = range int(numberOfMigrations) % maxResources {
			migration := &v1.VirtualMachineInstanceMigration{}
			cf.GenerateStruct(migration)
			
			if migration.Name == "" {
				migration.Name = "migration-" + rand.String(5)
			}
			if migration.Namespace == "" {
				migration.Namespace = k8sv1.NamespaceDefault
			}
			// Link to VMI if available
			if len(vmis) > 0 && migration.Spec.VMIName == "" {
				migration.Spec.VMIName = vmis[len(migrations)%len(vmis)].Name
			}
			migrations = append(migrations, migration)
		}

		if len(vmis)+len(nodes)+len(pods)+len(migrations) == 0 {
			return
		}

		stop := make(chan struct{})
		defer close(stop)
		ctrl := gomock.NewController(t)
		virtClient := kubecli.NewMockKubevirtClient(ctrl)
		fakeVirtClient := kubevirtfake.NewSimpleClientset()

		vmiInformer, vmiSource := testutils.NewFakeInformerWithIndexersFor(&v1.VirtualMachineInstance{}, cache.Indexers{
			cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
			"node": func(obj interface{}) (strings []string, e error) {
				return []string{obj.(*v1.VirtualMachineInstance).Status.NodeName}, nil
			},
		})
		migrationInformer, migrationSource := testutils.NewFakeInformerFor(&v1.VirtualMachineInstanceMigration{})
		nodeInformer, nodeSource := testutils.NewFakeInformerFor(&k8sv1.Node{})
		podInformer, podSource := testutils.NewFakeInformerFor(&k8sv1.Pod{})
		defer migrationSource.Shutdown()
		defer nodeSource.Shutdown()
		defer podSource.Shutdown()
		recorder := record.NewFakeRecorder(100)
		recorder.IncludeObject = true

		kv := &v1.KubeVirt{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kvObjectName,
				Namespace: kvObjectNamespace,
			},
			Spec: v1.KubeVirtSpec{
				Configuration: v1.KubeVirtConfiguration{},
			},
			Status: v1.KubeVirtStatus{
				DefaultArchitecture: stdruntime.GOARCH,
				Phase:               "Deployed",
			},
		}

		config, crdInformer, kubeVirtInformerStore, cs1, cs2 := NewFakeClusterConfigUsingKVConfig(kv)
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

		controller, _ := evacuation.NewEvacuationController(vmiInformer,
			migrationInformer,
			nodeInformer,
			podInformer,
			recorder,
			virtClient,
			config)
		controller.Queue.ShutDown()
		mockQueue := testutils.NewMockWorkQueue(controller.Queue)
		controller.Queue = mockQueue

		// Set up mock client
		virtClient.EXPECT().VirtualMachineInstanceMigration(k8sv1.NamespaceDefault).Return(fakeVirtClient.KubevirtV1().VirtualMachineInstanceMigrations(k8sv1.NamespaceDefault)).AnyTimes()
		kubeClient := fake.NewSimpleClientset()
		virtClient.EXPECT().CoreV1().Return(kubeClient.CoreV1()).AnyTimes()
		virtClient.EXPECT().PolicyV1().Return(kubeClient.PolicyV1()).AnyTimes()

		// Make sure that all unexpected calls to kubeClient will fail
		kubeClient.Fake.PrependReactor("*", "*", func(action k8sTesting.Action) (handled bool, obj runtime.Object, err error) {
			return true, nil, nil
		})

		syncCaches := func(stop chan struct{}) {
			go vmiInformer.Run(stop)
			go migrationInformer.Run(stop)
			go nodeInformer.Run(stop)
			go podInformer.Run(stop)

			cache.WaitForCacheSync(stop,
				vmiInformer.HasSynced,
				migrationInformer.HasSynced,
				nodeInformer.HasSynced,
				podInformer.HasSynced,
			)
		}

		syncCaches(stop)

		// Add the resources to the context
		for _, vmi := range vmis {
			key, err := virtController.KeyFunc(vmi)
			if err != nil {
				continue
			}
			controller.Queue.Add(key)
			vmiSource.Add(vmi)
		}
		for _, node := range nodes {
			key, err := virtController.KeyFunc(node)
			if err != nil {
				continue
			}
			controller.Queue.Add(key)
			nodeSource.Add(node)
		}
		for _, pod := range pods {
			key, err := virtController.KeyFunc(pod)
			if err != nil {
				continue
			}
			controller.Queue.Add(key)
			podSource.Add(pod)
		}
		for _, migration := range migrations {
			key, err := virtController.KeyFunc(migration)
			if err != nil {
				continue
			}
			controller.Queue.Add(key)
			migrationSource.Add(migration)
		}
		if controller.Queue.Len() == 0 {
			return
		}

		// Run the controller
		controller.Execute()
	})
}
