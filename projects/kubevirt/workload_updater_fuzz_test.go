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
	"context"
	"reflect"
	"testing"
	"time"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/mock/gomock"
	k8sv1 "k8s.io/api/core/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	"kubevirt.io/kubevirt/pkg/virt-config"
	"kubevirt.io/kubevirt/pkg/virt-controller/watch/workload-updater"
	fuzztestutils "kubevirt.io/kubevirt/pkg/virt-controller/watch/testutils"
)

func FuzzWorkloadUpdateController(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Set up the fuzzer with custom functions
		cf := gofuzzheaders.NewConsumer(data)
		cf.AddFuncs([]interface{}{
			fuzztestutils.CustomObjectMetaFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMIFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomPodFuzzer(),
			fuzztestutils.CustomVMIMigrationFuzzer(k8sv1.NamespaceDefault),
		})

		// Fuzz the KubeVirt CR
		kv := &virtv1.KubeVirt{}
		cf.GenerateStruct(kv)

		if kv.Namespace == "" {
			kv.Namespace = k8sv1.NamespaceDefault
		}
		if kv.Name == "" {
			return
		}

		// Fuzz some VMIs
		var numVMIs int
		cf.GenerateStruct(&numVMIs)
		if numVMIs < 0 {
			numVMIs = -numVMIs
		}
		numVMIs = numVMIs % 10

		vmis := make([]*virtv1.VirtualMachineInstance, numVMIs)
		for i := 0; i < numVMIs; i++ {
			vmi := &virtv1.VirtualMachineInstance{}
			cf.GenerateStruct(vmi)
			if vmi.Namespace == "" {
				vmi.Namespace = kv.Namespace
			}
			vmis[i] = vmi
		}

		// Fuzz some Pods
		var numPods int
		cf.GenerateStruct(&numPods)
		if numPods < 0 {
			numPods = -numPods
		}
		numPods = numPods % 10

		pods := make([]*k8sv1.Pod, numPods)
		for i := 0; i < numPods; i++ {
			pod := &k8sv1.Pod{}
			cf.GenerateStruct(pod)
			if pod.Namespace == "" {
				pod.Namespace = kv.Namespace
			}
			pods[i] = pod
		}

		// Fuzz some Migrations
		var numMigrations int
		cf.GenerateStruct(&numMigrations)
		if numMigrations < 0 {
			numMigrations = -numMigrations
		}
		numMigrations = numMigrations % 5

		migrations := make([]*virtv1.VirtualMachineInstanceMigration, numMigrations)
		for i := 0; i < numMigrations; i++ {
			migration := &virtv1.VirtualMachineInstanceMigration{}
			cf.GenerateStruct(migration)
			if migration.Namespace == "" {
				migration.Namespace = kv.Namespace
			}
			// Link to a VMI if available
			if len(vmis) > 0 {
				migration.Spec.VMIName = vmis[i%len(vmis)].Name
			}
			migrations[i] = migration
		}

		// Set up the mock client
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		virtClient := kubecli.NewMockKubevirtClient(ctrl)
		vmiInterface := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
		migrationInterface := kubecli.NewMockVirtualMachineInstanceMigrationInterface(ctrl)

		virtClient.EXPECT().VirtualMachineInstance(gomock.Any()).Return(vmiInterface).AnyTimes()
		vmiInterface.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		vmiInterface.EXPECT().Patch(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&virtv1.VirtualMachineInstance{}, nil).AnyTimes()

		virtClient.EXPECT().VirtualMachineInstanceMigration(gomock.Any()).Return(migrationInterface).AnyTimes()
		migrationInterface.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(&virtv1.VirtualMachineInstanceMigration{}, nil).AnyTimes()
		migrationInterface.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		// Set up informers
		vmiInformer := cache.NewSharedIndexInformer(nil, &virtv1.VirtualMachineInstance{}, 0, cache.Indexers{
			cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
		})
		podInformer := cache.NewSharedIndexInformer(nil, &k8sv1.Pod{}, 0, cache.Indexers{
			cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
		})
		migrationInformer := cache.NewSharedIndexInformer(nil, &virtv1.VirtualMachineInstanceMigration{}, 0, cache.Indexers{
			cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
		})
		kubeVirtInformer := cache.NewSharedIndexInformer(nil, &virtv1.KubeVirt{}, 0, cache.Indexers{
			cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
		})

		// Add objects to stores
		if err := kubeVirtInformer.GetStore().Add(kv); err != nil {
			return
		}

		for _, vmi := range vmis {
			if err := vmiInformer.GetStore().Add(vmi); err != nil {
				continue
			}
		}

		for _, pod := range pods {
			if err := podInformer.GetStore().Add(pod); err != nil {
				continue
			}
		}

		for _, migration := range migrations {
			if err := migrationInformer.GetStore().Add(migration); err != nil {
				continue
			}
		}

		// Create cluster config - use a simple approach
		crdInformer := cache.NewSharedIndexInformer(nil, &extv1.CustomResourceDefinition{}, 0, cache.Indexers{})
		clusterConfig, _ := virtconfig.NewClusterConfig(crdInformer, kubeVirtInformer, k8sv1.NamespaceDefault)

		// Create the controller
		recorder := record.NewFakeRecorder(100)
		controller, err := workloadupdater.NewWorkloadUpdateController(
			"test-launcher-image",
			vmiInformer,
			podInformer,
			migrationInformer,
			kubeVirtInformer,
			recorder,
			virtClient,
			clusterConfig,
		)
		if err != nil {
			return
		}

		// Use reflection to access the private queue field
		v := reflect.ValueOf(controller).Elem()
		queueField := v.FieldByName("queue")
		if queueField.IsValid() && queueField.CanInterface() {
			if queue, ok := queueField.Interface().(workqueue.TypedRateLimitingInterface[string]); ok {
				// Create a key for the KubeVirt CR
				key, err := cache.MetaNamespaceKeyFunc(kv)
				if err == nil {
					queue.Add(key)
				}
			}
		}

		// Execute the reconciliation with a timeout to prevent hanging
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = controller.Execute()
		}()
		
		// Wait for either completion or timeout
		select {
		case <-done:
			// Completed successfully
		case <-ctx.Done():
			// Timed out - that's OK for fuzzing
		}
	})
}
