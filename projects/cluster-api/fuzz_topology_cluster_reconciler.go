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
	"context"
	"fmt"
	"testing"

	"github.com/ghodss/yaml"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	//ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	//"sigs.k8s.io/cluster-api/internal/controllers/topology/cluster/scope"
	"sigs.k8s.io/cluster-api/internal/test/builder"
	//"sigs.k8s.io/cluster-api/internal/test/envtest"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"sync"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

var (
	fakeSchemeForFuzzing = runtime.NewScheme()
	//env                  *envtest.Environment
	//ctx                  = ctrl.SetupSignalHandler()
	fuzzCtx     = context.Background()
	initter sync.Once
)

func initFunc() {
	_ = clientgoscheme.AddToScheme(fakeSchemeForFuzzing)
	_ = clusterv1.AddToScheme(fakeSchemeForFuzzing)
	_ = apiextensionsv1.AddToScheme(fakeSchemeForFuzzing)
	_ = corev1.AddToScheme(fakeSchemeForFuzzing)
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

/*func validateBlueprint(b *scope.ClusterBlueprint) error {
	if b.ClusterClass == nil {
		return fmt.Errorf("ClusterClass is nil")
	}
	if b.ClusterClass.Spec.ControlPlane.MachineInfrastructure == nil {
		return fmt.Errorf("ClusterClass.Spec.ControlPlane.MachineInfrastructure is nil")
	}
	return nil
}*/

func validateUnstructured(unstr *unstructured.Unstructured) error {
	if _, ok := unstr.Object["kind"]; !ok {
		return fmt.Errorf("invalid unstr")
	}
	if _, ok := unstr.Object["apiVersion"]; !ok {
		return fmt.Errorf("invalid unstr")
	}
	if _, ok := unstr.Object["spec"]; !ok {
		return fmt.Errorf("invalid unstr")
	}
	if _, ok := unstr.Object["status"]; !ok {
		return fmt.Errorf("invalid unstr")
	}
	return nil
}

func FuzzClusterReconcile(f *testing.F) {
    f.Fuzz(func (t *testing.T, data []byte){
		fdp := fuzz.NewConsumer(data)
		unstr, err := GetUnstructured(fdp)
		if err != nil {
			return
		}
		err = validateUnstructured(unstr)
		if err != nil {
			return
		}
		cluster := &clusterv1.Cluster{}
		err = fdp.GenerateStruct(cluster)
		if err != nil {
			return
		}
		node := &corev1.Node{}
		err = fdp.GenerateStruct(node)
		if err != nil {
			return
		}
		clientFake := fake.NewClientBuilder().WithObjects(
			node,
			cluster,
			builder.GenericInfrastructureMachineCRD.DeepCopy(),
			unstr,
		).Build()
		r := &Reconciler{
			Client:    clientFake,
			APIReader: clientFake,
		}

		r.Reconcile(fuzzCtx, reconcile.Request{NamespacedName: util.ObjectKey(cluster)})
	})
}
