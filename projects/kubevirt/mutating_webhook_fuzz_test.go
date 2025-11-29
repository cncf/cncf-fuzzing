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

package mutating_webhook

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/client-go/kubevirt/fake"

	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"
)

func FuzzWebhookMutators(f *testing.F) {
	// Add seed to kickstart fuzzing
	f.Add([]byte(`{"apiVersion":"v1","kind":"VirtualMachine","metadata":{"name":"test-vm"}}`), uint8(0))
	
	f.Fuzz(func(t *testing.T, rawObject []byte, admitterType uint8) {
		// Don't fuzz the AdmissionRequest structure itself - it's too complex for gofuzz
		// Instead, fuzz only the Object.Raw field which contains the actual resource
		
		// Create a well-formed AdmissionRequest with only the object being fuzzed
		ar := &admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "AdmissionReview",
				APIVersion: "admission.k8s.io/v1",
			},
			Request: &admissionv1.AdmissionRequest{
				UID:       "test-uid",
				Name:      "test-name",
				Namespace: "default",
				Operation: admissionv1.Create,
				Kind: metav1.GroupVersionKind{
					Group:   "kubevirt.io",
					Version: "v1",
					Kind:    "VirtualMachine",
				},
				Object: runtime.RawExtension{
					Raw: rawObject,
				},
			},
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

		// Create a fuzzed cluster config
		clusterConfig := &virtconfig.ClusterConfig{}

		switch int(admitterType) % 3 {
		case 0:
			ServeVMs(resp, req, clusterConfig, virtClient)
		case 1:
			ServeMigrationCreate(resp, req)
		case 2:
			ServeClones(resp, req)
		}
	})
}
