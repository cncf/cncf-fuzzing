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

package validating_webhook

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/client-go/kubevirt/fake"

	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"
)

func FuzzWebhookAdmitters(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, admitterType uint8) {
		if len(data) < 50 {
			return
		}

		// Use go-fuzz-headers for efficient generation
		cf := gofuzzheaders.NewConsumer(data)

		// Create a realistic AdmissionReview
		ar := &admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "AdmissionReview",
				APIVersion: "admission.k8s.io/v1",
			},
			Request: &admissionv1.AdmissionRequest{},
		}

		// Fuzz the request
		if err := cf.GenerateStruct(ar.Request); err != nil {
			return
		}

		// Ensure request has required fields
		if ar.Request.UID == "" {
			ar.Request.UID = "test-uid"
		}
		if ar.Request.Name == "" {
			ar.Request.Name = "test-name"
		}
		if ar.Request.Namespace == "" {
			ar.Request.Namespace = "default"
		}
		if ar.Request.Object.Raw == nil {
			ar.Request.Object.Raw = []byte("{}")
		}

		marshaledBytes, err := json.Marshal(ar)
		if err != nil {
			return
		}
		req, err := http.NewRequest("POST", "http://example.com/validate", bytes.NewReader(marshaledBytes))
		if err != nil {
			return
		}
		req.Header.Add("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		ctrl := gomock.NewController(t)
		virtClient := kubecli.NewMockKubevirtClient(ctrl)
		virtClient.EXPECT().GeneratedKubeVirtClient().Return(fake.NewSimpleClientset()).AnyTimes()

		// Create a simple cluster config
		clusterConfig := &virtconfig.ClusterConfig{}
		kubeVirtServiceAccounts := make(map[string]struct{})

		switch int(admitterType) % 15 {
		case 0:
			ServeVMIUpdate(resp, req, clusterConfig, kubeVirtServiceAccounts)
		case 1:
			ServeVMIRS(resp, req, clusterConfig)
		case 2:
			ServeVMPool(resp, req, clusterConfig, kubeVirtServiceAccounts)
		case 3:
			ServeVMIPreset(resp, req)
		case 4:
			ServeMigrationCreate(resp, req, clusterConfig, virtClient, kubeVirtServiceAccounts)
		case 5:
			ServeMigrationUpdate(resp, req)
		case 6:
			ServeVMSnapshots(resp, req, clusterConfig, virtClient)
		case 7:
			ServeVMExports(resp, req, clusterConfig)
		case 8:
			ServeVmInstancetypes(resp, req)
		case 9:
			ServeVmClusterInstancetypes(resp, req)
		case 10:
			ServeVmPreferences(resp, req)
		case 11:
			ServeVmClusterPreferences(resp, req)
		case 12:
			ServeMigrationPolicies(resp, req)
		case 13:
			ServeVirtualMachineClones(resp, req, clusterConfig, virtClient)
		}
	})
}
