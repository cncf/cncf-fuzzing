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

package cluster

import (
	"fmt"

	"github.com/ghodss/yaml"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/internal/contract"
	"sigs.k8s.io/cluster-api/internal/controllers/topology/cluster/mergepatch"
	"sigs.k8s.io/cluster-api/internal/controllers/topology/cluster/scope"
	"sigs.k8s.io/cluster-api/internal/test/builder"
	"sigs.k8s.io/cluster-api/internal/test/envtest"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"sync"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

var (
	fakeSchemeForFuzzing = runtime.NewScheme()
	env                  *envtest.Environment
	ctx                  = ctrl.SetupSignalHandler()
	initter              sync.Once
)

func initFunc() {
	_ = clientgoscheme.AddToScheme(fakeSchemeForFuzzing)
	_ = clusterv1.AddToScheme(fakeSchemeForFuzzing)
	_ = apiextensionsv1.AddToScheme(fakeSchemeForFuzzing)
	_ = corev1.AddToScheme(fakeSchemeForFuzzing)
}

// tests cluster-api/internal/controllers/topology/cluster.(r *Reconciler).reconcileMachineHealthCheck()
func FuzzreconcileMachineHealthCheck(data []byte) int {
	initter.Do(initFunc)
	f := fuzz.NewConsumer(data)

	current := &clusterv1.MachineHealthCheck{}
	desired := &clusterv1.MachineHealthCheck{}

	err := f.GenerateStruct(current)
	if err != nil {
		return 0
	}
	err = f.GenerateStruct(desired)
	if err != nil {
		return 0
	}
	cp := builder.ControlPlane(metav1.NamespaceDefault, "cp1").Build()
	cp.SetUID("very-unique-identifier")

	r := Reconciler{
		Client: fake.NewClientBuilder().
			WithScheme(fakeSchemeForFuzzing).
			WithObjects([]client.Object{cp}...).
			Build(),
		recorder: record.NewFakeRecorder(32),
	}
	// Fuzz target:
	r.reconcileMachineHealthCheck(ctx, current, desired)
	return 1
}

// tests cluster-api/internal/controllers/topology/cluster.(r *Reconciler).reconcileReferencedObject()
func FuzzreconcileReferencedObject(data []byte) int {
	f := fuzz.NewConsumer(data)
	cluster := &clusterv1.Cluster{}
	err := f.GenerateStruct(cluster)
	if err != nil {
		return 0
	}
	current, err := GetUnstructured(f)
	if err != nil {
		return 0
	}
	desired, err := GetUnstructured(f)
	if err != nil {
		return 0
	}

	fakeClient := fake.NewClientBuilder().WithScheme(fakeSchemeForFuzzing).Build()
	r := Reconciler{
		Client: fakeClient,
		// NOTE: Intentionally using a fake recorder, so the test can also be run without testenv.
		recorder: record.NewFakeRecorder(32),
	}

	r.reconcileReferencedObject(ctx, reconcileReferencedObjectInput{
		cluster: cluster,
		current: current,
		desired: desired,
		opts: []mergepatch.HelperOption{
			mergepatch.AuthoritativePaths{
				// Note: Just using .spec.machineTemplate.metadata here as an example.
				contract.ControlPlane().MachineTemplate().Metadata().Path(),
			},
		}})
	return 1
}

// helper function to crate an unstructured object.
func GetUnstructured(f *fuzz.ConsumeFuzzer) (*unstructured.Unstructured, error) {
	yamlStr, err := f.GetString()
	if err != nil {
		return nil, err
	}
	obj := make(map[string]interface{})
	err = yaml.Unmarshal([]byte(yamlStr), &obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: obj}, nil
}

// tests cluster-api/internal/controllers/topology/cluster.(r *Reconciler).reconcileInfrastructureCluster()
func FuzzreconcileControlPlane(data []byte) int {
	f := fuzz.NewConsumer(data)
	cluster := &clusterv1.Cluster{}
	err := f.GenerateStruct(cluster)
	if err != nil {
		return 0
	}

	desiredCluster := &clusterv1.Cluster{}
	err = f.GenerateStruct(desiredCluster)
	if err != nil {
		return 0
	}
	desired := &scope.ClusterState{
		Cluster: desiredCluster,
		ControlPlane: &scope.ControlPlaneState{
			Object: builder.ControlPlane("ns1", "controlplane1").
				WithVersion("v1.21.2").
				WithReplicas(3).
				Build(),
		},
	}
	s := scope.New(cluster)
	s.Desired = desired

	fakeClient := fake.NewClientBuilder().WithScheme(fakeSchemeForFuzzing).Build()
	r := Reconciler{
		Client: fakeClient,
		// NOTE: Intentionally using a fake recorder, so the test can also be run without testenv.
		recorder: record.NewFakeRecorder(32),
	}
	err = r.reconcileControlPlane(ctx, s)
	if err != nil {
		fmt.Println(err)
	}
	return 1
}
