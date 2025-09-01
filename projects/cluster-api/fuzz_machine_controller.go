package machine

import (
	"context"
	"fmt"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/internal/test/builder"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

var (
	fuzzCtx              = context.Background()
	fakeSchemeForFuzzing = runtime.NewScheme()
)

func init() {
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

func FuzzMachineReconcile(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fdp := fuzz.NewConsumer(data)
		unstr, err := GetUnstructured(fdp)
		if err != nil {
			return
		}
		err = validateUnstructured(unstr)
		if err != nil {
			return
		}
		cluster := &clusterv1.Machine{}
		err = fdp.GenerateStruct(cluster)
		if err != nil {
			return
		}
		node := &corev1.Node{}
		err = fdp.GenerateStruct(node)
		if err != nil {
			return
		}
		clientFake := fake.NewClientBuilder().WithScheme(fakeSchemeForFuzzing).WithObjects(
			cluster,
			node,
			unstr,
			builder.GenericInfrastructureMachineCRD.DeepCopy(),
		).Build()
		r := &Reconciler{
			Client:    clientFake,
			APIReader: clientFake,
		}

		r.Reconcile(fuzzCtx, reconcile.Request{NamespacedName: util.ObjectKey(cluster)})
	})
}
