package patch

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	addonsv1 "sigs.k8s.io/cluster-api/exp/addons/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	ctx        = ctrl.SetupSignalHandler()
	fakeScheme = runtime.NewScheme()
	objTypes   = map[int]string{
		0: "Node",
		1: "Machine",
		2: "Deployment",
	}
	objects = []client.Object{&appsv1.Deployment{},
		&clusterv1.Machine{},
		&corev1.Node{},
		&addonsv1.ClusterResourceSet{},
		&addonsv1.ClusterResourceSetBinding{},
		&clusterv1.Cluster{},
		&clusterv1.ClusterClass{},
		&clusterv1.MachineSet{}}
)

func init() {
	_ = scheme.AddToScheme(fakeScheme)
	_ = clusterv1.AddToScheme(fakeScheme)
	_ = apiextensionsv1.AddToScheme(fakeScheme)
	_ = addonsv1.AddToScheme(fakeScheme)
}

func FuzzPatch(data []byte) int {
	//var obj client.Object
	f := fuzz.NewConsumer(data)
	objType, err := f.GetInt()
	if err != nil {
		return 0
	}
	obj := objects[objType%len(objects)]
	err = f.GenerateStruct(obj)
	if err != nil {
		return 0
	}
	patcher, err := NewHelper(obj, fake.NewClientBuilder().
		WithScheme(fakeScheme).
		WithObjects(obj).
		Build())
	if err != nil {
		return 0
	}
	err = f.GenerateStruct(obj)
	if err != nil {
		return 0
	}
	_ = patcher.Patch(ctx, obj)
	return 1
}
