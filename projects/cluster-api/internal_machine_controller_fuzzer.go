// Copyright 2022 ADA Logics Ltd
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

package machine

import (
	"context"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/internal/test/builder"
	"sigs.k8s.io/cluster-api/util/kubeconfig"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

var (
	ctx            = context.Background()
	fakeScheme     = runtime.NewScheme()
	defaultCluster = &clusterv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: metav1.NamespaceDefault,
		},
	}
	defaultBootstrap = &unstructured.Unstructured{
		Object: map[string]interface{}{
			"kind":       "GenericBootstrapConfig",
			"apiVersion": "bootstrap.cluster.x-k8s.io/v1beta1",
			"metadata": map[string]interface{}{
				"name":      "bootstrap-config1",
				"namespace": metav1.NamespaceDefault,
			},
			"spec":   map[string]interface{}{},
			"status": map[string]interface{}{},
		},
	}

	defaultInfra = &unstructured.Unstructured{
		Object: map[string]interface{}{
			"kind":       "GenericInfrastructureMachine",
			"apiVersion": "infrastructure.cluster.x-k8s.io/v1beta1",
			"metadata": map[string]interface{}{
				"name":      "infra-config1",
				"namespace": metav1.NamespaceDefault,
			},
			"spec":   map[string]interface{}{},
			"status": map[string]interface{}{},
		},
	}
)

func init() {
	_ = scheme.AddToScheme(fakeScheme)
	_ = clusterv1.AddToScheme(fakeScheme)
	_ = apiextensionsv1.AddToScheme(fakeScheme)
}

func FuzzMachineController_reconcile(data []byte) int {
	f := fuzz.NewConsumer(data)
	machine := &clusterv1.Machine{}
	err := f.GenerateStruct(machine)
	if err != nil {
		return 0
	}
	var defaultKubeconfigSecret *corev1.Secret
	defaultKubeconfigSecret = kubeconfig.GenerateSecret(defaultCluster, kubeconfig.FromEnvTestConfig(&rest.Config{}, defaultCluster))

	bootstrapConfig := defaultBootstrap.DeepCopy()
	infraConfig := defaultInfra.DeepCopy()

	fakeClient := fake.NewClientBuilder().
		WithScheme(fakeScheme).
		WithObjects(defaultCluster,
			defaultKubeconfigSecret,
			machine,
			builder.GenericBootstrapConfigCRD.DeepCopy(),
			builder.GenericInfrastructureMachineCRD.DeepCopy(),
			bootstrapConfig,
			infraConfig,
		).Build()
	r := &Reconciler{
		Client:    fakeClient,
		APIReader: fakeClient,
	}
	if r.Client == nil {
		panic("client must not be nil")
	}
	_, err = r.reconcile(ctx, defaultCluster, machine)
	if err != nil {
		return 0
	}
	r.reconcilePhase(ctx, machine)
	return 1
}
