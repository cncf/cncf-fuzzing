// Copyright 2021 ADA Logics Ltd
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

package fuzzing

import (
	"reflect"
	"sync"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/api/legacyscheme"

	appsv1 "k8s.io/api/apps/v1"
	appsv1beta1 "k8s.io/api/apps/v1beta1"
	appsv1beta2 "k8s.io/api/apps/v1beta2"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2beta1 "k8s.io/api/autoscaling/v2beta1"
	autoscalingv2 "k8s.io/api/autoscaling/v2beta2"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	v1 "k8s.io/api/core/v1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	schedulingv1alpha1 "k8s.io/api/scheduling/v1alpha1"
	schedulingv1beta1 "k8s.io/api/scheduling/v1beta1"
	storagev1 "k8s.io/api/storage/v1"
	storagev1beta1 "k8s.io/api/storage/v1beta1"

	_ "k8s.io/kubernetes/pkg/apis/apps/install"
	_ "k8s.io/kubernetes/pkg/apis/autoscaling/install"
	_ "k8s.io/kubernetes/pkg/apis/batch/install"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	_ "k8s.io/kubernetes/pkg/apis/extensions/install"
	_ "k8s.io/kubernetes/pkg/apis/networking/install"
	_ "k8s.io/kubernetes/pkg/apis/scheduling/install"
	_ "k8s.io/kubernetes/pkg/apis/storage/install"

	appsv1SGV "k8s.io/kubernetes/pkg/apis/apps/v1"
	appsv1beta1SGV "k8s.io/kubernetes/pkg/apis/apps/v1beta1"
	appsv1beta2SGV "k8s.io/kubernetes/pkg/apis/apps/v1beta2"
	autoscalingV1SGV "k8s.io/kubernetes/pkg/apis/autoscaling/v1"
	autoscalingV2beta1SGV "k8s.io/kubernetes/pkg/apis/autoscaling/v2beta1"
	autoscalingV2beta2SGV "k8s.io/kubernetes/pkg/apis/autoscaling/v2beta2"
	batchV1SGV "k8s.io/kubernetes/pkg/apis/batch/v1"
	batchV1beta1SGV "k8s.io/kubernetes/pkg/apis/batch/v1beta1"
	corev1SGV "k8s.io/kubernetes/pkg/apis/core/v1"
	extensionsV1beta1SGV "k8s.io/kubernetes/pkg/apis/extensions/v1beta1"
	networkingV1SGV "k8s.io/kubernetes/pkg/apis/networking/v1"
	networkingV1beta1SGV "k8s.io/kubernetes/pkg/apis/networking/v1beta1"
)

var (
	initLocalTest sync.Once
	totalFuncs    = 39
)

// initTesting implements an init function that
// is invoked using sync.Do. It is only used
// by a few of the fuzzers, and its invocation
// is therefore isolated to those.
func initTesting() {
	testing.Init()
}

/*
FuzzRoundtrip implements a fuzzer for the logic
of the following roundtrip tests:
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/apps/v1/defaults_test.go#L585
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/apps/v1beta1/defaults_test.go#L199
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/apps/v1beta2/defaults_test.go#L551
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/autoscaling/v1/defaults_test.go#L137
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/autoscaling/v2beta1/defaults_test.go#L176
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/autoscaling/v2beta2/defaults_test.go#L306
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/batch/v1/defaults_test.go#L310
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/batch/v1beta1/defaults_test.go#L93
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/core/v1/defaults_test.go#L396
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/extensions/v1beta1/defaults_test.go#L736
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/networking/v1/defaults_test.go#L367
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/networking/v1beta1/defaults_test.go#L82
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/scheduling/v1/defaults_test.go#L35
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/scheduling/v1alpha1/defaults_test.go#L35
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/scheduling/v1beta1/defaults_test.go#L35
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/storage/v1/defaults_test.go#L33
- https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/storage/v1beta1/defaults_test.go#L33
*/
func FuzzRoundtrip(data []byte) int {
	if len(data) < 10 {
		return 0
	}
	op := int(data[0])
	inputData := data[1:]
	if op%totalFuncs == 0 {
		return FuzzAppsV1DaemonSet(inputData)
	} else if op%totalFuncs == 1 {
		return FuzzAppsV1StatefulSet(inputData)
	} else if op%totalFuncs == 2 {
		return FuzzAppsV1Deployment(inputData)
	} else if op%totalFuncs == 3 {
		return FuzzAppsV1beta1(inputData)
	} else if op%totalFuncs == 4 {
		return FuzzAppsV1beta2StatefulSet(inputData)
	} else if op%totalFuncs == 5 {
		return FuzzAppsV1beta2Deployment(inputData)
	} else if op%totalFuncs == 6 {
		return FuzzAppsV1beta2ReplicaSet(inputData)
	} else if op%totalFuncs == 7 {
		return FuzzAppsV1beta2DaemonSet(inputData)
	} else if op%totalFuncs == 8 {
		return FuzzAutoscalingV1HorizontalPodAutoscaler(inputData)
	} else if op%totalFuncs == 9 {
		return FuzzAutoscalingV2beta1HorizontalPodAutoscaler(inputData)
	} else if op%totalFuncs == 10 {
		return FuzzAutoscalingV2beta2HorizontalPodAutoscaler(inputData)
	} else if op%totalFuncs == 11 {
		return FuzzBatchV1Job(inputData)
	} else if op%totalFuncs == 12 {
		return FuzzBatchV1CronJob(inputData)
	} else if op%totalFuncs == 13 {
		return FuzzBatchV1beta1CronJob(inputData)
	} else if op%totalFuncs == 14 {
		return FuzzCoreV1ReplicationController(inputData)
	} else if op%totalFuncs == 15 {
		return FuzzCoreV1Pod(inputData)
	} else if op%totalFuncs == 16 {
		return FuzzCoreV1Secret(inputData)
	} else if op%totalFuncs == 17 {
		return FuzzCoreV1PersistentVolume(inputData)
	} else if op%totalFuncs == 18 {
		return FuzzCoreV1PersistentVolumeClaim(inputData)
	} else if op%totalFuncs == 19 {
		return FuzzCoreV1Endpoints(inputData)
	} else if op%totalFuncs == 20 {
		return FuzzCoreV1Service(inputData)
	} else if op%totalFuncs == 21 {
		return FuzzCoreV1Namespace(inputData)
	} else if op%totalFuncs == 22 {
		return FuzzCoreV1Node(inputData)
	} else if op%totalFuncs == 23 {
		return FuzzCoreV1Endpoints(inputData)
	} else if op%totalFuncs == 24 {
		return FuzzCoreV1LimitRange(inputData)
	} else if op%totalFuncs == 25 {
		return FuzzExtensionsV1beta1DaemonSet(inputData)
	} else if op%totalFuncs == 26 {
		return FuzzExtensionsV1beta1Deployment(inputData)
	} else if op%totalFuncs == 27 {
		return FuzzExtensionsV1beta1ReplicaSet(inputData)
	} else if op%totalFuncs == 28 {
		return FuzzExtensionsV1beta1NetworkPolicy(inputData)
	} else if op%totalFuncs == 29 {
		return FuzzNetworkingV1NetworkPolicy(inputData)
	} else if op%totalFuncs == 30 {
		return FuzzNetworkingV1IngressClass(inputData)
	} else if op%totalFuncs == 31 {
		return FuzzNetworkingV1beta1Ingress(inputData)
	} else if op%totalFuncs == 32 {
		return FuzzSchedulingV1PriorityClass(inputData)
	} else if op%totalFuncs == 33 {
		return FuzzSchedulingV1alpa1PriorityClass(inputData)
	} else if op%totalFuncs == 34 {
		return FuzzSchedulingV1beta1PriorityClass(inputData)
	} else if op%totalFuncs == 35 {
		return FuzzStorageV1CSIDriver(inputData)
	} else if op%totalFuncs == 36 {
		return FuzzStorageV1StorageClass(inputData)
	} else if op%totalFuncs == 37 {
		return FuzzStorageV1beta1CSIDriver(inputData)
	} else if op%totalFuncs == 38 {
		return FuzzStorageV1beta1StorageClass(inputData)
	}
	return 1
}

func FuzzAppsV1DaemonSet(data []byte) int {
	o := &appsv1.DaemonSet{}
	sgv := appsv1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzAppsV1StatefulSet(data []byte) int {
	o := &appsv1.StatefulSet{}
	sgv := appsv1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzAppsV1Deployment(data []byte) int {
	o := &appsv1.Deployment{}
	sgv := appsv1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzAppsV1beta1(data []byte) int {
	o := &appsv1beta1.Deployment{}
	sgv := appsv1beta1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzAppsV1beta2StatefulSet(data []byte) int {
	o := &appsv1beta2.StatefulSet{}
	sgv := appsv1beta2SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzAppsV1beta2Deployment(data []byte) int {
	o := &appsv1beta2.Deployment{}
	sgv := appsv1beta2SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzAppsV1beta2ReplicaSet(data []byte) int {
	o := &appsv1beta2.ReplicaSet{}
	sgv := appsv1beta2SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzAppsV1beta2DaemonSet(data []byte) int {
	o := &appsv1beta2.DaemonSet{}
	sgv := appsv1beta2SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzAutoscalingV1HorizontalPodAutoscaler(data []byte) int {
	o := &autoscalingv1.HorizontalPodAutoscaler{}
	sgv := autoscalingV1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzAutoscalingV2beta1HorizontalPodAutoscaler(data []byte) int {
	o := &autoscalingv2beta1.HorizontalPodAutoscaler{}
	sgv := autoscalingV2beta1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzAutoscalingV2beta2HorizontalPodAutoscaler(data []byte) int {
	o := &autoscalingv2.HorizontalPodAutoscaler{}
	sgv := autoscalingV2beta2SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzBatchV1Job(data []byte) int {
	o := &batchv1.Job{}
	sgv := batchV1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzBatchV1CronJob(data []byte) int {
	o := &batchv1.CronJob{}
	sgv := batchV1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

// Scheme IS registered
func FuzzBatchV1beta1CronJob(data []byte) int {
	o := &batchv1beta1.CronJob{}
	sgv := batchV1beta1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzCoreV1ReplicationController(data []byte) int {
	o := &v1.ReplicationController{}
	sgv := corev1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzCoreV1Pod(data []byte) int {
	o := &v1.Pod{}
	sgv := corev1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzCoreV1Secret(data []byte) int {
	o := &v1.Secret{}
	sgv := corev1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzCoreV1PersistentVolume(data []byte) int {
	o := &v1.PersistentVolume{}
	sgv := corev1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzCoreV1PersistentVolumeClaim(data []byte) int {
	o := &v1.PersistentVolumeClaim{}
	sgv := corev1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzCoreV1Endpoints(data []byte) int {
	o := &v1.Endpoints{}
	sgv := corev1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzCoreV1Service(data []byte) int {
	o := &v1.Service{}
	sgv := corev1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzCoreV1Namespace(data []byte) int {
	o := &v1.Namespace{}
	sgv := corev1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzCoreV1Node(data []byte) int {
	o := &v1.Node{}
	sgv := corev1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzCoreV1LimitRange(data []byte) int {
	o := &v1.LimitRange{}
	sgv := corev1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzExtensionsV1beta1DaemonSet(data []byte) int {
	o := &extensionsv1beta1.DaemonSet{}
	sgv := extensionsV1beta1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzExtensionsV1beta1Deployment(data []byte) int {
	o := &extensionsv1beta1.Deployment{}
	sgv := extensionsV1beta1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzExtensionsV1beta1ReplicaSet(data []byte) int {
	o := &extensionsv1beta1.ReplicaSet{}
	sgv := extensionsV1beta1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzExtensionsV1beta1NetworkPolicy(data []byte) int {
	o := &extensionsv1beta1.NetworkPolicy{}
	sgv := extensionsV1beta1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzNetworkingV1NetworkPolicy(data []byte) int {
	o := &networkingv1.NetworkPolicy{}
	sgv := networkingV1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzNetworkingV1IngressClass(data []byte) int {
	o := &networkingv1.IngressClass{}
	sgv := networkingV1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzNetworkingV1beta1Ingress(data []byte) int {
	o := &networkingv1beta1.Ingress{}
	sgv := networkingV1beta1SGV.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzSchedulingV1PriorityClass(data []byte) int {
	o := &schedulingv1.PriorityClass{}
	sgv := schedulingv1.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzSchedulingV1alpa1PriorityClass(data []byte) int {
	o := &schedulingv1alpha1.PriorityClass{}
	sgv := schedulingv1alpha1.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzSchedulingV1beta1PriorityClass(data []byte) int {
	o := &schedulingv1beta1.PriorityClass{}
	sgv := schedulingv1beta1.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzStorageV1CSIDriver(data []byte) int {
	initLocalTest.Do(initTesting)
	o := &storagev1.CSIDriver{}
	sgv := storagev1.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzStorageV1StorageClass(data []byte) int {
	initLocalTest.Do(initTesting)
	o := &storagev1.StorageClass{}
	sgv := storagev1.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzStorageV1beta1CSIDriver(data []byte) int {
	initLocalTest.Do(initTesting)
	o := &storagev1beta1.CSIDriver{}
	sgv := storagev1beta1.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func FuzzStorageV1beta1StorageClass(data []byte) int {
	initLocalTest.Do(initTesting)
	o := &storagev1beta1.StorageClass{}
	sgv := storagev1beta1.SchemeGroupVersion
	prepAndDoRoundtrip(sgv, o, data)
	return 1
}

func prepAndDoRoundtrip(sgv schema.GroupVersion, o runtime.Object, data []byte) error {
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(o)
	if err != nil {
		return err
	}

	// First test:
	// Do a roundtrip
	_ = roundTrip(runtime.Object(o), sgv)

	// Second test:
	// Call only runtime.Decode with the Legacy codec and the UniversalDecoder
	// and some input data that hasn't been derived from encoding.
	data2, err := f.GetBytes()
	if err != nil {
		return err
	}
	_, _ = runtime.Decode(legacyscheme.Codecs.LegacyCodec(sgv), data2)
	_, _ = runtime.Decode(legacyscheme.Codecs.UniversalDecoder(), data2)
	return nil
}

func roundTrip(obj runtime.Object, sgv schema.GroupVersion) runtime.Object {
	data, err := runtime.Encode(legacyscheme.Codecs.LegacyCodec(sgv), obj)
	if err != nil {
		return obj
	}
	obj2, err := runtime.Decode(legacyscheme.Codecs.UniversalDecoder(), data)
	if err != nil {
		panic(err)
	}
	obj3 := reflect.New(reflect.TypeOf(obj).Elem()).Interface().(runtime.Object)
	err = legacyscheme.Scheme.Convert(obj2, obj3, nil)
	if err != nil {
		panic(err)
	}
	return obj3
}
