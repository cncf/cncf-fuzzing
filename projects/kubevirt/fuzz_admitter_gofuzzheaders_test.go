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
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	v1 "kubevirt.io/api/core/v1"
	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"

	instancetypeWebhooks "kubevirt.io/kubevirt/pkg/instancetype/webhooks/vm"
	"kubevirt.io/kubevirt/pkg/virt-api/webhooks"
	"kubevirt.io/kubevirt/pkg/virt-api/webhooks/validating-webhook/admitters"
	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"
)

// FuzzAdmitterFast - Fast-starting fuzzer using go-fuzz-headers
func FuzzAdmitterFast(f *testing.F) {
	// Use Default config for speed
	cfg := gofuzzheaders.DefaultConfig()

	// Single minimal seed
	f.Add([]byte{0})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 5 {
			return
		}

		// Use first byte to determine VMI or VM
		isVMI := (data[0] & 1) == 0
		cf := gofuzzheaders.NewConsumerWithConfig(data[1:], cfg)

		if isVMI {
			// Fuzz VirtualMachineInstance
			var vmi v1.VirtualMachineInstance
			if err := cf.GenerateStruct(&vmi); err != nil {
				return
			}

			request := toAdmissionReview(&vmi, webhooks.VirtualMachineInstanceGroupVersionResource)
			config := fuzzKubeVirtConfig(int64(data[0]))

			const kubeVirtNamespace = "kubevirt"
			adm := &admitters.VMICreateAdmitter{
				ClusterConfig:           config,
				KubeVirtServiceAccounts: webhooks.KubeVirtServiceAccounts(kubeVirtNamespace),
			}
			_ = adm.Admit(context.Background(), request)
		} else {
			// Fuzz VirtualMachine
			var vm v1.VirtualMachine
			if err := cf.GenerateStruct(&vm); err != nil {
				return
			}

			request := toAdmissionReview(&vm, webhooks.VirtualMachineGroupVersionResource)
			config := fuzzKubeVirtConfig(int64(data[0]))

			const kubeVirtNamespace = "kubevirt"
			adm := &admitters.VMsAdmitter{
				ClusterConfig:           config,
				KubeVirtServiceAccounts: webhooks.KubeVirtServiceAccounts(kubeVirtNamespace),
				InstancetypeAdmitter:    instancetypeWebhooks.NewAdmitterStub(),
			}
			_ = adm.Admit(context.Background(), request)
		}
	})
}

func toAdmissionReview(obj interface{}, gvr metav1.GroupVersionResource) *admissionv1.AdmissionReview {
	bytes, _ := json.Marshal(obj)
	return &admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			Resource: gvr,
			Object: runtime.RawExtension{
				Raw: bytes,
			},
		},
	}
}

func fuzzKubeVirtConfig(seed int64) *virtconfig.ClusterConfig {
	// Use default cluster config
	config, _ := virtconfig.NewClusterConfig(nil, nil, "")
	return config
}
