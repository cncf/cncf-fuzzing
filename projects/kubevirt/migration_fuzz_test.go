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
	stdruntime "runtime"
	"testing"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/mock/gomock"
	k8sv1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	framework "k8s.io/client-go/tools/cache/testing"
	"k8s.io/client-go/tools/record"
	v1 "kubevirt.io/api/core/v1"
	migrationsv1 "kubevirt.io/api/migrations/v1alpha1"
	"kubevirt.io/client-go/kubecli"
	kubevirtfake "kubevirt.io/client-go/kubevirt/fake"
	"kubevirt.io/client-go/log"
	fakenetworkclient "kubevirt.io/client-go/networkattachmentdefinitionclient/fake"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"

	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"
	"kubevirt.io/kubevirt/pkg/virt-controller/services"

	virtcontroller "kubevirt.io/kubevirt/pkg/controller"
	"kubevirt.io/kubevirt/pkg/testutils"
	"kubevirt.io/kubevirt/pkg/virt-controller/watch/migration"
	fuzztestutils "kubevirt.io/kubevirt/pkg/virt-controller/watch/testutils"
)

var (
	maxResources            = 3
	qemuGid           int64 = 107
	kvObjectNamespace       = "kubevirt"
	kvObjectName            = "kubevirt"
)

// mockNetworkAnnotationsGenerator is a simple mock implementation
type mockNetworkAnnotationsGenerator struct{}

func (m *mockNetworkAnnotationsGenerator) GenerateFromActivePod(vmi *v1.VirtualMachineInstance, pod *k8sv1.Pod) map[string]string {
	return map[string]string{}
}

func NewFakeClusterConfigUsingKV(kv *v1.KubeVirt) (*virtconfig.ClusterConfig, cache.SharedIndexInformer, cache.SharedIndexInformer, cache.Store, *framework.FakeControllerSource, *framework.FakeControllerSource) {
	return NewFakeClusterConfigUsingKVWithCPUArch(kv, stdruntime.GOARCH)
}

func NewFakeClusterConfigUsingKVWithCPUArch(kv *v1.KubeVirt, CPUArch string) (*virtconfig.ClusterConfig, cache.SharedIndexInformer, cache.SharedIndexInformer, cache.Store, *framework.FakeControllerSource, *framework.FakeControllerSource) {
	kv.ResourceVersion = rand.String(10)
	kv.Status.Phase = "Deployed"
	crdInformer, cs1 := testutils.NewFakeInformerFor(&extv1.CustomResourceDefinition{})
	kubeVirtInformer, cs2 := testutils.NewFakeInformerFor(&v1.KubeVirt{})

	kubeVirtInformer.GetStore().Add(kv)

	AddDataVolumeAPI(crdInformer)
	cfg, _ := virtconfig.NewClusterConfigWithCPUArch(crdInformer, kubeVirtInformer, kvObjectNamespace, CPUArch)
	return cfg, crdInformer, kubeVirtInformer, kubeVirtInformer.GetStore(), cs1, cs2
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

func NewFakeClusterConfigUsingKVConfig(kv *v1.KubeVirt) (*virtconfig.ClusterConfig, cache.SharedIndexInformer, cache.SharedIndexInformer, cache.Store, *framework.FakeControllerSource, *framework.FakeControllerSource) {
	return NewFakeClusterConfigUsingKV(kv)
}

// FuzzExecute addd up to 3 resources
// to the context and then runs the controller.
func FuzzExecute(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte,
		numberOfVMIs,
		numberOfVMIMigrations,
		numberOfNodes,
		numberOfPDBs,
		numberOfMPs uint8) {
		
		// Create fuzzer with custom functions for valid K8s objects
		cf := gofuzzheaders.NewConsumer(data)
		cf.AddFuncs([]interface{}{
			fuzztestutils.CustomObjectMetaFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMIFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMIMigrationFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomNodeFuzzer(),
			fuzztestutils.CustomPodDisruptionBudgetFuzzer(),
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
			vmis = append(vmis, vmi)
		}

		vmiMigrations := make([]*v1.VirtualMachineInstanceMigration, 0)
		for _ = range int(numberOfVMIMigrations) % maxResources {
			vmiMigration := &v1.VirtualMachineInstanceMigration{}
			cf.GenerateStruct(vmiMigration)
			
			// Ensure metadata and VMI reference
			if vmiMigration.Name == "" {
				vmiMigration.Name = "migration-" + rand.String(5)
			}
			if vmiMigration.Namespace == "" {
				vmiMigration.Namespace = k8sv1.NamespaceDefault
			}
			// Link to a VMI if available
			if len(vmis) > 0 && vmiMigration.Spec.VMIName == "" {
				vmiMigration.Spec.VMIName = vmis[0].Name
			}
			vmiMigrations = append(vmiMigrations, vmiMigration)
		}

		nodes := make([]*k8sv1.Node, 0)
		for _ = range int(numberOfNodes) % maxResources {
			node := &k8sv1.Node{}
			cf.GenerateStruct(node)
			nodes = append(nodes, node)
		}

		pdbs := make([]*policyv1.PodDisruptionBudget, 0)
		for _ = range int(numberOfPDBs) % maxResources {
			pdb := &policyv1.PodDisruptionBudget{}
			cf.GenerateStruct(pdb)
			
			// Ensure metadata
			if pdb.Name == "" {
				pdb.Name = "pdb-" + rand.String(5)
			}
			if pdb.Namespace == "" {
				pdb.Namespace = k8sv1.NamespaceDefault
			}
			pdbs = append(pdbs, pdb)
		}

		mps := make([]*migrationsv1.MigrationPolicy, 0)
		for _ = range int(numberOfMPs) % maxResources {
			mp := &migrationsv1.MigrationPolicy{}
			cf.GenerateStruct(mp)
			
			// Ensure metadata
			if mp.Name == "" {
				mp.Name = "mp-" + rand.String(5)
			}
			mps = append(mps, mp)
		}

		// ignore logs
		var b bytes.Buffer
		log.Log.SetIOWriter(bufio.NewWriter(&b))

		virtClient := kubecli.NewMockKubevirtClient(gomock.NewController(t))
		virtClientset := kubevirtfake.NewSimpleClientset()

		vmiInformer, vmiCs := testutils.NewFakeInformerFor(&v1.VirtualMachineInstance{})
		migrationInformer, migrationCs := testutils.NewFakeInformerFor(&v1.VirtualMachineInstanceMigration{})
		podInformer, podCs := testutils.NewFakeInformerFor(&k8sv1.Pod{})
		pdbInformer, pdbCs := testutils.NewFakeInformerFor(&policyv1.PodDisruptionBudget{})
		resourceQuotaInformer, resourceQuotaCs := testutils.NewFakeInformerFor(&k8sv1.ResourceQuota{})
		namespaceInformer, nsCs := testutils.NewFakeInformerFor(&k8sv1.Namespace{})
		migrationPolicyInformer, migrationPolicyCs := testutils.NewFakeInformerFor(&migrationsv1.MigrationPolicy{})
		nodeInformer, nodeCs := testutils.NewFakeInformerFor(&k8sv1.Node{})
		pvcInformer, pvcCs := testutils.NewFakeInformerFor(&k8sv1.PersistentVolumeClaim{})
		storageClassInformer, storageClassCs := testutils.NewFakeInformerFor(&storagev1.StorageClass{})
		storageProfileInformer, storageProfileCs := testutils.NewFakeInformerFor(&cdiv1.StorageProfile{})
		defer vmiCs.Shutdown()
		defer migrationCs.Shutdown()
		defer podCs.Shutdown()
		defer pdbCs.Shutdown()
		defer resourceQuotaCs.Shutdown()
		defer nsCs.Shutdown()
		defer migrationPolicyCs.Shutdown()
		defer nodeCs.Shutdown()
		defer pvcCs.Shutdown()
		defer storageClassCs.Shutdown()
		defer storageProfileCs.Shutdown()

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

		config, crdInformer, kubevirtInformer, kubeVirtInformerStore, cs1, cs2 := NewFakeClusterConfigUsingKVConfig(kv)
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
		controller, _ := migration.NewController(
			services.NewTemplateService("a", 240, "b", "c", "d", "e", "f", pvcInformer.GetStore(), virtClient, config, qemuGid, "g", resourceQuotaInformer.GetStore(), namespaceInformer.GetStore()),
			vmiInformer,
			podInformer,
			migrationInformer,
			nodeInformer,
			pvcInformer,
			storageClassInformer,
			storageProfileInformer,
			migrationPolicyInformer,
			resourceQuotaInformer,
			kubevirtInformer,
			recorder,
			virtClient,
			config,
			&mockNetworkAnnotationsGenerator{},
		)
		// Wrap our workqueue to have a way to detect when we are done processing updates
		mockQueue := testutils.NewMockPriorityQueue(controller.Queue)
		controller.Queue.ShutDown()
		controller.Queue = mockQueue

		// Set up mock client
		kubeClient := fake.NewSimpleClientset()
		virtClient.EXPECT().VirtualMachineInstanceMigration(k8sv1.NamespaceDefault).Return(virtClientset.KubevirtV1().VirtualMachineInstanceMigrations(k8sv1.NamespaceDefault)).AnyTimes()
		virtClient.EXPECT().VirtualMachineInstance(k8sv1.NamespaceDefault).Return(virtClientset.KubevirtV1().VirtualMachineInstances(k8sv1.NamespaceDefault)).AnyTimes()
		virtClient.EXPECT().CoreV1().Return(kubeClient.CoreV1()).AnyTimes()
		virtClient.EXPECT().PolicyV1().Return(kubeClient.PolicyV1()).AnyTimes()
		networkClient := fakenetworkclient.NewSimpleClientset()
		virtClient.EXPECT().NetworkClient().Return(networkClient).AnyTimes()
		virtClient.EXPECT().MigrationPolicy().Return(virtClientset.MigrationsV1alpha1().MigrationPolicies()).AnyTimes()

		// Add the resources to the context
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
		for _, vmiMigration := range vmiMigrations {

			var addToQueue bool
			var create bool
			cf.GenerateStruct(&addToQueue)
			cf.GenerateStruct(&create)

			if addToQueue {
				key, err := virtcontroller.KeyFunc(vmiMigration)
				if err != nil {
					return
				}
				mockQueue.Add(key)
			}
			if create {
				virtClientset.KubevirtV1().VirtualMachineInstanceMigrations(vmiMigration.Namespace).Create(context.Background(), vmiMigration, metav1.CreateOptions{})
				virtClient.EXPECT().VirtualMachineInstanceMigration(vmiMigration.Namespace).Return(virtClientset.KubevirtV1().VirtualMachineInstanceMigrations(vmiMigration.Namespace)).AnyTimes()
			}
		}
		for _, node := range nodes {
			err := nodeInformer.GetStore().Add(node)
			if err != nil {
				return
			}
			kubeClient.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{})

		}
		for _, pdb := range pdbs {
			var addToStore bool
			var create bool
			cf.GenerateStruct(&addToStore)
			cf.GenerateStruct(&create)

			if addToStore {
				err := pdbInformer.GetIndexer().Add(pdb)
				if err != nil {
					return
				}
			}
			if create {
				kubeClient.PolicyV1().PodDisruptionBudgets(pdb.Namespace).Create(context.Background(), pdb, metav1.CreateOptions{})
			}
		}
		for _, mp := range mps {
			var addToStore bool
			var create bool
			cf.GenerateStruct(&addToStore)
			cf.GenerateStruct(&create)

			if addToStore {
				err := migrationPolicyInformer.GetStore().Add(mp)
				if err != nil {
					return
				}
			}
			if create {
				virtClientset.MigrationsV1alpha1().MigrationPolicies().Create(context.Background(), mp, metav1.CreateOptions{})
			}
		}
		if mockQueue.Len() == 0 {
			return
		}

		// Run the controller
		controller.Execute()
	})
}
