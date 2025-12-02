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
	"testing"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/mock/gomock"
	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	"kubevirt.io/kubevirt/pkg/virt-controller/watch/replicaset"
	fuzztestutils "kubevirt.io/kubevirt/pkg/virt-controller/watch/testutils"
)

func FuzzReplicaSetController(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// Set up go-fuzz-headers consumer
		cf := gofuzzheaders.NewConsumer(data)
		
		// Add custom functions
		cf.AddFuncs([]interface{}{
			fuzztestutils.CustomObjectMetaFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMIFuzzer(k8sv1.NamespaceDefault),
			fuzztestutils.CustomVMIReplicaSetFuzzer(k8sv1.NamespaceDefault),
		})

		// Fuzz the VirtualMachineInstanceReplicaSet
		rs := &virtv1.VirtualMachineInstanceReplicaSet{}
		if err := cf.GenerateStruct(rs); err != nil {
			return
		}

		// Ensure basic validity
		if rs.Namespace == "" {
			rs.Namespace = k8sv1.NamespaceDefault
		}
		if rs.Name == "" {
			return
		}

		// Ensure spec is not nil
		if rs.Spec.Template == nil {
			rs.Spec.Template = &virtv1.VirtualMachineInstanceTemplateSpec{}
		}
		if rs.Spec.Selector == nil {
			rs.Spec.Selector = &metav1.LabelSelector{}
		}

		// Ensure template labels match selector
		if len(rs.Spec.Template.ObjectMeta.Labels) == 0 {
			rs.Spec.Template.ObjectMeta.Labels = map[string]string{"app": "test"}
		}
		if rs.Spec.Selector.MatchLabels == nil {
			rs.Spec.Selector.MatchLabels = rs.Spec.Template.ObjectMeta.Labels
		}

		// Fuzz some VMIs that might be owned by this ReplicaSet
		var numVMIs int
		if err := cf.GenerateStruct(&numVMIs); err != nil {
			numVMIs = 5
		}
		if numVMIs < 0 {
			numVMIs = -numVMIs
		}
		numVMIs = numVMIs % 10 // Limit to reasonable number

		vmis := make([]*virtv1.VirtualMachineInstance, numVMIs)
		for i := 0; i < numVMIs; i++ {
			vmi := &virtv1.VirtualMachineInstance{}
			if err := cf.GenerateStruct(vmi); err != nil {
				continue
			}

			if vmi.Namespace == "" {
				vmi.Namespace = rs.Namespace
			}

			// Some VMIs should match the ReplicaSet selector
			if i%2 == 0 {
				vmi.Labels = rs.Spec.Template.ObjectMeta.Labels
				// Set owner reference
				vmi.OwnerReferences = []metav1.OwnerReference{
					*metav1.NewControllerRef(rs, virtv1.VirtualMachineInstanceReplicaSetGroupVersionKind),
				}
			}

			vmis[i] = vmi
		}

		// Set up the mock client
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		virtClient := kubecli.NewMockKubevirtClient(ctrl)
		rsInterface := kubecli.NewMockReplicaSetInterface(ctrl)
		vmiInterface := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)

		// Allow ReplicaSet().Get() for adoption checks
		virtClient.EXPECT().ReplicaSet(gomock.Any()).Return(rsInterface).AnyTimes()
		rsInterface.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).Return(rs, nil).AnyTimes()
		rsInterface.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).Return(rs, nil).AnyTimes()
		rsInterface.EXPECT().UpdateStatus(gomock.Any(), gomock.Any(), gomock.Any()).Return(rs, nil).AnyTimes()

		// Allow VMI operations
		virtClient.EXPECT().VirtualMachineInstance(gomock.Any()).Return(vmiInterface).AnyTimes()
		vmiInterface.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).Return(&virtv1.VirtualMachineInstance{}, nil).AnyTimes()
		vmiInterface.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		// Set up informers
		vmiInformer := cache.NewSharedIndexInformer(nil, &virtv1.VirtualMachineInstance{}, 0, cache.Indexers{
			cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
		})
		rsInformer := cache.NewSharedIndexInformer(nil, &virtv1.VirtualMachineInstanceReplicaSet{}, 0, cache.Indexers{
			cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
		})

		// Add the ReplicaSet to the store
		if err := rsInformer.GetStore().Add(rs); err != nil {
			return
		}

		// Add VMIs to the store
		for _, vmi := range vmis {
			if err := vmiInformer.GetStore().Add(vmi); err != nil {
				continue
			}
		}

		// Create the controller
		recorder := record.NewFakeRecorder(100)
		controller, err := replicaset.NewController(vmiInformer, rsInformer, recorder, virtClient, 10)
		if err != nil {
			return
		}

		// Create a key for the ReplicaSet
		key, err := cache.MetaNamespaceKeyFunc(rs)
		if err != nil {
			return
		}

		// Add to queue
		controller.Queue.Add(key)

		// Execute the reconciliation
		// We don't check for errors as we're fuzzing - panics are what we care about
		_ = controller.Execute()
	})
}
