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

package patch

import (
	"testing"
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
	fuzzCtx    = ctrl.SetupSignalHandler()
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

func FuzzPatch(f *testing.F) {
    f.Fuzz(func (t *testing.T, data []byte){
		//var obj client.Object
		fdp := fuzz.NewConsumer(data)
		objType, err := fdp.GetInt()
		if err != nil {
			return
		}
		obj := objects[objType%len(objects)]
		err = fdp.GenerateStruct(obj)
		if err != nil {
			return
		}
		patcher, err := NewHelper(obj, fake.NewClientBuilder().
			WithScheme(fakeScheme).
			WithObjects(obj).
			Build())
		if err != nil {
			return
		}
		err = fdp.GenerateStruct(obj)
		if err != nil {
			return
		}
		patcher.Patch(fuzzCtx, obj)
	})
}
