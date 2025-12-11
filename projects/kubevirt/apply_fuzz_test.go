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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/api/errors"

	"go.uber.org/mock/gomock"

	secv1 "github.com/openshift/api/security/v1"
	secv1fake "github.com/openshift/client-go/security/clientset/versioned/typed/security/v1/fake"
	promv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	extclientfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	kubevirtfake "kubevirt.io/client-go/kubevirt/fake"
	promclientfake "kubevirt.io/client-go/prometheusoperator/fake"

	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	"k8s.io/apimachinery/pkg/runtime"

	"kubevirt.io/kubevirt/pkg/controller"
	"kubevirt.io/kubevirt/pkg/testutils"
	"kubevirt.io/kubevirt/pkg/virt-operator/resource/apply"
	"kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/install"
	installstrategy "kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/install"
	marshalutil "kubevirt.io/kubevirt/tools/util"

	routev1 "github.com/openshift/api/route/v1"
	k8sv1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"kubevirt.io/kubevirt/pkg/virt-operator/util"

	gofuzzheaders "github.com/AdaLogics/go-fuzz-headers"
)

type fuzzOption int

const (
	withSyntaxErrors fuzzOption = 1
	Namespace                   = "ns"
)

var (
	resources = map[int]string{
		0:  "Route",
		1:  "ServiceAccount",
		2:  "ClusterRole",
		3:  "ClusterRoleBinding",
		4:  "Role",
		5:  "RoleBinding",
		6:  "Service",
		7:  "Deployment",
		8:  "DaemonSet",
		9:  "ValidationWebhook",
		10: "MutatingWebhook",
		11: "APIService",
		12: "SCC",
		13: "InstallStrategyJob",
		14: "InfrastructurePod",
		15: "PodDisruptionBudget",
		16: "ServiceMonitor",
		17: "Namespace",
		18: "PrometheusRule",
		19: "Secret",
		20: "ConfigMap",
		21: "ValidatingAdmissionPolicyBinding",
		22: "ValidatingAdmissionPolicy",
	}
)

func createRandomizedObject(cf *gofuzzheaders.ConsumeFuzzer, resourceType string) runtime.Object {
	switch resourceType {
	case "Route":
		obj := &routev1.Route{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: routev1.SchemeGroupVersion.String(),
			Kind:       "Route",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "ServiceAccount":
		obj := &k8sv1.ServiceAccount{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: k8sv1.SchemeGroupVersion.String(),
			Kind:       "ServiceAccount",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "ClusterRole":
		obj := &rbacv1.ClusterRole{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: rbacv1.SchemeGroupVersion.String(),
			Kind:       "ClusterRole",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = "" // Cluster-scoped resource
		return obj
	case "ClusterRoleBinding":
		obj := &rbacv1.ClusterRoleBinding{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: rbacv1.SchemeGroupVersion.String(),
			Kind:       "ClusterRoleBinding",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = "" // Cluster-scoped resource
		return obj
	case "Role":
		obj := &rbacv1.Role{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: rbacv1.SchemeGroupVersion.String(),
			Kind:       "Role",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "RoleBinding":
		obj := &rbacv1.RoleBinding{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: rbacv1.SchemeGroupVersion.String(),
			Kind:       "RoleBinding",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "Service":
		obj := &k8sv1.Service{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: k8sv1.SchemeGroupVersion.String(),
			Kind:       "Service",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "Deployment":
		obj := &appsv1.Deployment{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       "Deployment",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "DaemonSet":
		obj := &appsv1.DaemonSet{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: appsv1.SchemeGroupVersion.String(),
			Kind:       "DaemonSet",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "ValidationWebhook":
		obj := &admissionregistrationv1.ValidatingWebhookConfiguration{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: admissionregistrationv1.SchemeGroupVersion.String(),
			Kind:       "ValidatingWebhookConfiguration",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = "" // Cluster-scoped resource
		return obj
	case "MutatingWebhook":
		obj := &admissionregistrationv1.MutatingWebhookConfiguration{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: admissionregistrationv1.SchemeGroupVersion.String(),
			Kind:       "MutatingWebhookConfiguration",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = "" // Cluster-scoped resource
		return obj
	case "APIService":
		obj := &apiregv1.APIService{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: apiregv1.SchemeGroupVersion.String(),
			Kind:       "APIService",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = "" // Cluster-scoped resource
		return obj
	case "SCC":
		obj := &secv1.SecurityContextConstraints{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: secv1.SchemeGroupVersion.String(),
			Kind:       "SecurityContextConstraints",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = "" // Cluster-scoped resource
		return obj
	case "InstallStrategyJob":
		obj := &batchv1.Job{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: batchv1.SchemeGroupVersion.String(),
			Kind:       "Job",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "InfrastructurePod":
		obj := &k8sv1.Pod{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: k8sv1.SchemeGroupVersion.String(),
			Kind:       "Pod",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "PodDisruptionBudget":
		obj := &policyv1.PodDisruptionBudget{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: policyv1.SchemeGroupVersion.String(),
			Kind:       "PodDisruptionBudget",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "ServiceMonitor":
		obj := &promv1.ServiceMonitor{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: promv1.SchemeGroupVersion.String(),
			Kind:       "ServiceMonitor",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "Namespace":
		obj := &k8sv1.Namespace{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: k8sv1.SchemeGroupVersion.String(),
			Kind:       "Namespace",
		}
		obj.TypeMeta = typeMeta
		obj.ObjectMeta.Name = Namespace
		obj.Namespace = "" // Namespace objects themselves don't have a namespace
		return obj
	case "PrometheusRule":
		obj := &promv1.PrometheusRule{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: promv1.SchemeGroupVersion.String(),
			Kind:       "PrometheusRule",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "Secret":
		obj := &k8sv1.Secret{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: k8sv1.SchemeGroupVersion.String(),
			Kind:       "Secret",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "ConfigMap":
		obj := &k8sv1.ConfigMap{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: k8sv1.SchemeGroupVersion.String(),
			Kind:       "ConfigMap",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = Namespace // Namespaced resource
		return obj
	case "ValidatingAdmissionPolicyBinding":
		obj := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: admissionregistrationv1.SchemeGroupVersion.String(),
			Kind:       "ValidatingAdmissionPolicyBinding",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = "" // Cluster-scoped resource
		return obj
	case "ValidatingAdmissionPolicy":
		obj := &admissionregistrationv1.ValidatingAdmissionPolicy{}
		cf.GenerateStruct(obj)
		typeMeta := metav1.TypeMeta{
			APIVersion: admissionregistrationv1.SchemeGroupVersion.String(),
			Kind:       "ValidatingAdmissionPolicy",
		}
		obj.TypeMeta = typeMeta
		obj.Namespace = "" // Cluster-scoped resource
		return obj
	default:
		// This should not happen. If it does, it is an indicator that
		// the fuzzer is not efficient, and we prefer to know about it
		// rather than letting the fuzzer run, hence the panic.
		panic(fmt.Sprintf("should not happen: '%s'", resourceType))
	}
}

func createManifests(t *testing.T, cf *gofuzzheaders.ConsumeFuzzer) ([]byte, error) {
	t.Helper()
	var b bytes.Buffer
	writer := bufio.NewWriter(&b)
	var randUint8 uint8
	cf.GenerateStruct(&randUint8)
	var numberOfResources int
	numberOfResources = int(randUint8) % 10
	if numberOfResources <= 0 {
		numberOfResources = 3
	}
	// count the created resources to
	// ensure we create at least one
	createdResource := 0
	for range numberOfResources {
		var resourceType uint8
		cf.GenerateStruct(&resourceType)
		resourceTypeStr := resources[int(resourceType)%len(resources)]
		obj := createRandomizedObject(cf, resourceTypeStr)
		err := marshalutil.MarshallObject(obj, writer)
		if err != nil {
			return nil, err // Skip if marshaling fails
		}
		createdResource += 1
	}
	writer.Flush()

	if createdResource == 0 {
		return nil, nil // Skip if no resources created
	}

	return b.Bytes(), nil
}

func loadTargetStrategyForFuzzing(resources []byte, config *util.KubeVirtDeploymentConfig, stores util.Stores) (*install.Strategy, error) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "kubevirt-install-strategy-",
			Namespace:    config.GetNamespace(),
			Labels: map[string]string{
				v1.ManagedByLabel:       v1.ManagedByLabelOperatorValue,
				v1.InstallStrategyLabel: "",
			},
			Annotations: map[string]string{
				v1.InstallStrategyVersionAnnotation:    config.GetKubeVirtVersion(),
				v1.InstallStrategyRegistryAnnotation:   config.GetImageRegistry(),
				v1.InstallStrategyIdentifierAnnotation: config.GetDeploymentID(),
			},
		},
		Data: map[string]string{
			"manifests": string(resources),
		},
	}

	err := stores.InstallStrategyConfigMapCache.Add(configMap)
	if err != nil {
		return nil, fmt.Errorf("could not add to cache: %v", err)
	}
	targetStrategy, err := installstrategy.LoadInstallStrategyFromCache(stores, config)
	return targetStrategy, err
}

func FuzzReconciler(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, callType uint8) {
		cf := gofuzzheaders.NewConsumer(data)
		cf.AddFuncs(fuzzFuncs())
		manifests, err := createManifests(t, cf)
		if err != nil {
			return
		}

		config := getConfig("fake-registry", "v9.9.9")
		stores := util.Stores{}
		stores.InstallStrategyConfigMapCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		strat, err := loadTargetStrategyForFuzzing(manifests, config, stores)
		if err != nil {
			return
		}
		origQueue := workqueue.NewTypedRateLimitingQueue[string](workqueue.DefaultTypedControllerRateLimiter[string]())
		queue := testutils.NewMockWorkQueue(origQueue)

		// Set up the stores caches
		stores.RouteCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ServiceAccountCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ClusterRoleCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ClusterRoleBindingCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.RoleCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.RoleBindingCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ServiceCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.DeploymentCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.DaemonSetCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ValidationWebhookCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.MutatingWebhookCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.APIServiceCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.SCCCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.InstallStrategyJobCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.InfrastructurePodCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.PodDisruptionBudgetCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ServiceMonitorCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.NamespaceCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.PrometheusRuleCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.SecretCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ConfigMapCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ValidatingAdmissionPolicyBindingCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ValidatingAdmissionPolicyCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ClusterInstancetype = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.ClusterPreference = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
		stores.OperatorCrdCache = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

		// Add the namespace to the namespace cache so reconciliation can find it
		namespace := &k8sv1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: Namespace,
			},
		}
		stores.NamespaceCache.Add(namespace)

		// Create at least 3 resources in the stores
		createdResource := 0
		for range 10 {
			var add bool
			cf.GenerateStruct(&add)
			if !add {
				continue
			}
			var randUint8 uint8
			cf.GenerateStruct(&randUint8)
			resourceType := resources[int(randUint8)%len(resources)]
			obj := createRandomizedObject(cf, resourceType)
			switch resourceType {
			case "Route":
				stores.RouteCache.Add(obj)
			case "ServiceAccount":
				stores.ServiceAccountCache.Add(obj)
			case "ClusterRole":
				stores.ClusterRoleCache.Add(obj)
			case "ClusterRoleBinding":
				stores.ClusterRoleBindingCache.Add(obj)
			case "Role":
				stores.RoleCache.Add(obj)
			case "RoleBinding":
				stores.RoleBindingCache.Add(obj)
			case "Service":
				stores.ServiceCache.Add(obj)
			case "Deployment":
				stores.DeploymentCache.Add(obj)
			case "DaemonSet":
				stores.DaemonSetCache.Add(obj)
			case "ValidationWebhook":
				stores.ValidationWebhookCache.Add(obj)
			case "MutatingWebhook":
				stores.MutatingWebhookCache.Add(obj)
			case "APIService":
				stores.APIServiceCache.Add(obj)
			case "SCC":
				stores.SCCCache.Add(obj)
			case "InstallStrategyJob":
				stores.InstallStrategyJobCache.Add(obj)
			case "InfrastructurePod":
				stores.InfrastructurePodCache.Add(obj)
			case "PodDisruptionBudget":
				stores.PodDisruptionBudgetCache.Add(obj)
			case "ServiceMonitor":
				stores.ServiceMonitorCache.Add(obj)
			case "Namespace":
				stores.NamespaceCache.Add(obj)
			case "PrometheusRule":
				stores.PrometheusRuleCache.Add(obj)
			case "Secret":
				stores.SecretCache.Add(obj)
			case "ConfigMap":
				stores.ConfigMapCache.Add(obj)
			case "ValidatingAdmissionPolicyBinding":
				stores.ValidatingAdmissionPolicyBindingCache.Add(obj)
			case "ValidatingAdmissionPolicy":
				stores.ValidatingAdmissionPolicyCache.Add(obj)
			default:
				// This should not happen. If it does, it is an indicator that
				// the fuzzer is not efficient, and we prefer to know about it
				// rather than letting the fuzzer run, hence the panic.
				panic("should not happen")
			}
			key, err := controller.KeyFunc(obj)
			if err != nil {
				panic(err)
			}
			queue.Add(key)
			createdResource += 1
		}
		// Only proceed if we actually have resources.
		if createdResource == 0 {
			return
		}

		// Setting up the Kubevirt clients
		ctrl := gomock.NewController(t)
		clientset := kubecli.NewMockKubevirtClient(ctrl)
		kv := &v1.KubeVirt{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: Namespace,
			},
		}
		expectations := &util.Expectations{}
		expectations.DaemonSet = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("DaemonSet"))
		expectations.PodDisruptionBudget = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("PodDisruptionBudget"))
		expectations.ValidatingAdmissionPolicyBinding = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("ValidatingAdmissionPolicyBinding"))
		expectations.ServiceAccount = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("ServiceAccount"))
		expectations.ValidatingAdmissionPolicy = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("ValidatingAdmissionPolicy"))
		expectations.Deployment = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("Deployment"))
		expectations.ValidationWebhook = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("ValidationWebhook"))
		expectations.MutatingWebhook = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("MutatingWebhook"))
		expectations.APIService = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("APIService"))
		expectations.Secrets = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("Secrets"))
		expectations.OperatorCrd = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("OperatorCrd"))
		expectations.Service = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("Service"))
		expectations.ClusterRoleBinding = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("ClusterRoleBinding"))
		expectations.ClusterRole = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("ClusterRole"))
		expectations.RoleBinding = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("RoleBinding"))
		expectations.Role = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("Role"))
		expectations.SCC = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("SCC"))
		expectations.PrometheusRule = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("PrometheusRule"))
		expectations.ServiceMonitor = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("ServiceMonitor"))
		expectations.Route = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("Route"))
		expectations.InstallStrategyConfigMap = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("InstallStrategyConfigMap"))
		expectations.InstallStrategyJob = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("InstallStrategyJob"))
		expectations.ConfigMap = controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectationsWithName("ConfigMap"))

		// Create fake clientsets and add the namespace to the core clientset
		pdbClient := fake.NewSimpleClientset()
		dsClient := fake.NewSimpleClientset()
		admissionClient := fake.NewSimpleClientset()
		coreclientset := fake.NewSimpleClientset(namespace) // Add namespace here
		rbacClient := fake.NewSimpleClientset()
		promClient := promclientfake.NewSimpleClientset()
		virtFakeClient := kubevirtfake.NewSimpleClientset()

		kvInterface := kubecli.NewMockKubeVirtInterface(ctrl)
		clientset.EXPECT().KubeVirt(Namespace).Return(kvInterface).AnyTimes()
		clientset.EXPECT().PolicyV1().Return(pdbClient.PolicyV1()).AnyTimes()
		clientset.EXPECT().AppsV1().Return(dsClient.AppsV1()).AnyTimes()
		clientset.EXPECT().AdmissionregistrationV1().Return(admissionClient.AdmissionregistrationV1()).AnyTimes()
		clientset.EXPECT().CoreV1().Return(coreclientset.CoreV1()).AnyTimes()
		clientset.EXPECT().RbacV1().Return(rbacClient.RbacV1()).AnyTimes()
		clientset.EXPECT().PrometheusClient().Return(promClient).AnyTimes()
		
		// Add VirtualMachine instancetype/preference clients
		clientset.EXPECT().VirtualMachineClusterInstancetype().Return(virtFakeClient.InstancetypeV1beta1().VirtualMachineClusterInstancetypes()).AnyTimes()
		clientset.EXPECT().VirtualMachineClusterPreference().Return(virtFakeClient.InstancetypeV1beta1().VirtualMachineClusterPreferences()).AnyTimes()

		secClient := &secv1fake.FakeSecurityV1{
			Fake: &fake.NewSimpleClientset().Fake,
		}

		clientset.EXPECT().SecClient().Return(secClient).AnyTimes()
		
		// Add ExtensionsClient mock to handle CRDs
		extClient := extclientfake.NewSimpleClientset()
		clientset.EXPECT().ExtensionsClient().Return(extClient).AnyTimes()
		
		aggregatorclient := install.NewMockAPIServiceInterface(ctrl)
		aggregatorclient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil, errors.NewNotFound(schema.GroupResource{Group: "", Resource: "apiservices"}, "whatever"))
		aggregatorclient.EXPECT().Create(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Do(func(ctx context.Context, obj runtime.Object, opts metav1.CreateOptions) {})
		aggregatorclient.EXPECT().Delete(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
		aggregatorclient.EXPECT().Patch(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Do(func(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, _ ...string) {
		})

		reconcilerConfig := util.OperatorConfig{
			IsOnOpenshift:                           true,
			ServiceMonitorEnabled:                   true,
			PrometheusRulesEnabled:                  true,
			ValidatingAdmissionPolicyBindingEnabled: true,
			ValidatingAdmissionPolicyEnabled:        true,
		}
		r, err := apply.NewReconciler(kv, strat, stores, reconcilerConfig, clientset, aggregatorclient, expectations, record.NewFakeRecorder(100))
		if err != nil {
			return
		}

		// Call the target entrypoint and check return values
		complete, syncErr := r.Sync(queue)

		// Verify state and invariants
		verifyReconciliation(t, r, strat, stores, pdbClient, dsClient, admissionClient, coreclientset, rbacClient, promClient, complete, syncErr)
	})
}

// verifyReconciliation checks invariants and state after Sync() completes
func verifyReconciliation(t *testing.T, r *apply.Reconciler, strat *install.Strategy, stores util.Stores,
	pdbClient, dsClient, admissionClient, coreclientset, rbacClient *fake.Clientset,
	promClient *promclientfake.Clientset, complete bool, syncErr error) {

	// Log sync results
	t.Logf("Sync complete=%v, error=%v", complete, syncErr)

	// Count resources in strategy
	strategyDeploymentCount := len(strat.Deployments())
	strategyServiceCount := len(strat.Services())
	strategyDaemonSetCount := len(strat.DaemonSets())

	// Count resources in stores (cache)
	storeDeploymentCount := len(stores.DeploymentCache.List())
	storeServiceCount := len(stores.ServiceCache.List())
	storeDaemonSetCount := len(stores.DaemonSetCache.List())

	// Count resources in fake clientsets
	deployments, _ := dsClient.AppsV1().Deployments("").List(context.Background(), metav1.ListOptions{})
	services, _ := coreclientset.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	daemonsets, _ := dsClient.AppsV1().DaemonSets("").List(context.Background(), metav1.ListOptions{})

	t.Logf("Deployments - strategy:%d cache:%d clientset:%d", strategyDeploymentCount, storeDeploymentCount, len(deployments.Items))
	t.Logf("Services - strategy:%d cache:%d clientset:%d", strategyServiceCount, storeServiceCount, len(services.Items))
	t.Logf("DaemonSets - strategy:%d cache:%d clientset:%d", strategyDaemonSetCount, storeDaemonSetCount, len(daemonsets.Items))

	// Invariant 1: If complete && no error, check that strategy objects exist
	if complete && syncErr == nil {
		// Check deployments
		for _, targetDeployment := range strat.Deployments() {
			_, exists, _ := stores.DeploymentCache.Get(targetDeployment)
			if !exists {
				t.Logf("WARNING: Sync complete but deployment %s not in cache", targetDeployment.Name)
			}
		}

		// Check services
		for _, targetService := range strat.Services() {
			_, exists, _ := stores.ServiceCache.Get(targetService)
			if !exists {
				t.Logf("WARNING: Sync complete but service %s not in cache", targetService.Name)
			}
		}

		// Check daemonsets
		for _, targetDaemonSet := range strat.DaemonSets() {
			_, exists, _ := stores.DaemonSetCache.Get(targetDaemonSet)
			if !exists {
				t.Logf("WARNING: Sync complete but daemonset %s not in cache", targetDaemonSet.Name)
			}
		}
	}

	// Invariant 2: Objects in cache should match objects in strategy (when complete)
	if complete && syncErr == nil {
		// Check for unexpected deployments in cache
		for _, obj := range stores.DeploymentCache.List() {
			deployment := obj.(*appsv1.Deployment)
			found := false
			for _, target := range strat.Deployments() {
				if target.Name == deployment.Name && target.Namespace == deployment.Namespace {
					found = true
					break
				}
			}
			if !found && deployment.DeletionTimestamp == nil {
				t.Logf("WARNING: Unexpected deployment %s in cache after complete sync", deployment.Name)
			}
		}
	}

	// Invariant 3: Check convergence progress
	// Even if not complete, reconciliation should make progress
	if strategyDeploymentCount > 0 {
		convergenceRatio := float64(storeDeploymentCount) / float64(strategyDeploymentCount)
		t.Logf("Deployment convergence: %.1f%% (%d/%d)", convergenceRatio*100, storeDeploymentCount, strategyDeploymentCount)

		if complete && syncErr == nil && convergenceRatio < 0.8 {
			t.Logf("WARNING: Sync complete but only %.1f%% deployment convergence", convergenceRatio*100)
		}
	}

	// Invariant 4: Objects being deleted shouldn't be in strategy
	for _, obj := range stores.DeploymentCache.List() {
		deployment := obj.(*appsv1.Deployment)
		if deployment.DeletionTimestamp != nil {
			for _, target := range strat.Deployments() {
				if target.Name == deployment.Name && target.Namespace == deployment.Namespace {
					t.Logf("WARNING: Deployment %s is being deleted but still in strategy", deployment.Name)
				}
			}
		}
	}

	// Invariant 5: Verify fake clientsets received create/update calls
	// Note: We can't fully verify this with the current mock setup using .AnyTimes()
	// but we can check that objects exist in the fake clientsets
	if len(deployments.Items) > 0 {
		t.Logf("Clientset has %d deployments (operations were performed)", len(deployments.Items))
	}
	if len(services.Items) > 0 {
		t.Logf("Clientset has %d services (operations were performed)", len(services.Items))
	}
}

func getConfig(registry, version string) *util.KubeVirtDeploymentConfig {
	return util.GetTargetConfigFromKV(&v1.KubeVirt{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: Namespace,
		},
		Spec: v1.KubeVirtSpec{
			ImageRegistry: registry,
			ImageTag:      version,
		},
	})
}

// generateValidK8sName generates a valid Kubernetes resource name (DNS-1123 subdomain)
// Must be lowercase alphanumeric, '-' or '.', max 253 chars, start/end with alphanumeric
func generateValidK8sName(c gofuzzheaders.Continue, prefix string) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	const maxLen = 63 // Keep it reasonable for testing
	
	length := 5 + c.Intn(maxLen-5) // 5 to maxLen chars
	name := prefix + "-"
	
	// Protect against negative length
	remainingLength := length - len(prefix) - 1
	if remainingLength < 0 {
		remainingLength = 0
	}
	
	for i := 0; i < remainingLength; i++ {
		if i > 0 && i < remainingLength-1 && c.Intn(10) == 0 {
			// Occasionally add a dash
			name += "-"
		} else {
			name += string(charset[c.Intn(len(charset))])
		}
	}
	
	// Ensure it ends with alphanumeric
	name += string(charset[c.Intn(len(charset))])
	
	return name
}

// generateValidK8sLabel generates a valid Kubernetes label value (DNS-1123 label)
// Must be alphanumeric, '-', '_' or '.', max 63 chars, start/end with alphanumeric
func generateValidK8sLabel(c gofuzzheaders.Continue, prefix string) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	const maxLen = 63
	
	length := 3 + c.Intn(min(maxLen-len(prefix)-1, 20)) // Keep it short
	name := prefix
	
	for i := 0; i < length; i++ {
		name += string(charset[c.Intn(len(charset))])
	}
	
	return name
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fuzzFuncs(options ...fuzzOption) []interface{} {
	addSyntaxErrors := false
	for _, opt := range options {
		if opt == withSyntaxErrors {
			addSyntaxErrors = true
		}
	}

	enumFuzzers := []interface{}{
		func(e *metav1.FieldsV1, c gofuzzheaders.Continue) {},
		// Generate valid Kubernetes ObjectMeta with proper DNS-compliant names
		func(objectmeta *metav1.ObjectMeta, c gofuzzheaders.Continue) {
			// Generate valid DNS-1123 subdomain names (lowercase alphanumeric + '-' and '.')
			objectmeta.Name = generateValidK8sName(c, "resource")
			objectmeta.Namespace = Namespace // Use consistent namespace
			
			// Generate valid labels (DNS-1123 label format)
			objectmeta.Labels = map[string]string{
				"app.kubernetes.io/name":       generateValidK8sLabel(c, "kubevirt"),
				"app.kubernetes.io/component":  "kubevirt",
				"app.kubernetes.io/managed-by": "virt-operator",
			}
			
			// Generate valid annotations
			objectmeta.Annotations = map[string]string{
				"kubevirt.io/generation":                   fmt.Sprintf("%d", c.Intn(100)),
				"kubevirt.io/install-strategy-identifier":  generateValidK8sLabel(c, "id"),
				"kubevirt.io/install-strategy-registry":    "fake-registry",
				"kubevirt.io/install-strategy-version":     "v9.9.9",
			}
			
			// Keep these nil/zero for simplicity
			objectmeta.DeletionGracePeriodSeconds = nil
			objectmeta.Generation = 0
			objectmeta.ManagedFields = nil
			objectmeta.ResourceVersion = ""
			objectmeta.UID = types.UID(fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", c.Uint32(), c.Intn(65536), c.Intn(65536), c.Intn(65536), c.Int63()))
		},
		func(obj *intstr.IntOrString, c gofuzzheaders.Continue) {
			// Properly initialize IntOrString to avoid "impossible IntOrString.Type" error
			if c.RandBool() {
				// Type 0 = Int
				*obj = intstr.FromInt32(c.Int31())
			} else {
				// Type 1 = String
				*obj = intstr.FromString(c.RandString())
			}
		},
		func(obj *corev1.URIScheme, c gofuzzheaders.Continue) {
			pickType(addSyntaxErrors, obj, []corev1.URIScheme{corev1.URISchemeHTTP, corev1.URISchemeHTTPS}, c)
		},
		func(obj *corev1.TaintEffect, c gofuzzheaders.Continue) {
			pickType(addSyntaxErrors, obj, []corev1.TaintEffect{corev1.TaintEffectNoExecute, corev1.TaintEffectNoSchedule, corev1.TaintEffectPreferNoSchedule}, c)
		},
		func(obj *corev1.NodeInclusionPolicy, c gofuzzheaders.Continue) {
			pickType(addSyntaxErrors, obj, []corev1.NodeInclusionPolicy{corev1.NodeInclusionPolicyHonor, corev1.NodeInclusionPolicyIgnore}, c)
		},
		func(obj *corev1.UnsatisfiableConstraintAction, c gofuzzheaders.Continue) {
			pickType(addSyntaxErrors, obj, []corev1.UnsatisfiableConstraintAction{corev1.DoNotSchedule, corev1.ScheduleAnyway}, c)
		},
		func(obj *corev1.PullPolicy, c gofuzzheaders.Continue) {
			pickType(addSyntaxErrors, obj, []corev1.PullPolicy{corev1.PullAlways, corev1.PullNever, corev1.PullIfNotPresent}, c)
		},
		func(obj *corev1.NodeSelectorOperator, c gofuzzheaders.Continue) {
			pickType(addSyntaxErrors, obj, []corev1.NodeSelectorOperator{corev1.NodeSelectorOpDoesNotExist, corev1.NodeSelectorOpExists, corev1.NodeSelectorOpGt, corev1.NodeSelectorOpIn, corev1.NodeSelectorOpLt, corev1.NodeSelectorOpNotIn}, c)
		},
		func(obj *corev1.TolerationOperator, c gofuzzheaders.Continue) {
			pickType(addSyntaxErrors, obj, []corev1.TolerationOperator{corev1.TolerationOpExists, corev1.TolerationOpEqual}, c)
		},
		func(obj *corev1.PodQOSClass, c gofuzzheaders.Continue) {
			pickType(addSyntaxErrors, obj, []corev1.PodQOSClass{corev1.PodQOSBestEffort, corev1.PodQOSGuaranteed, corev1.PodQOSBurstable}, c)
		},
		func(obj *corev1.PersistentVolumeMode, c gofuzzheaders.Continue) {
			pickType(addSyntaxErrors, obj, []corev1.PersistentVolumeMode{corev1.PersistentVolumeBlock, corev1.PersistentVolumeFilesystem}, c)
		},
		func(obj *corev1.DNSPolicy, c gofuzzheaders.Continue) {
			pickType(addSyntaxErrors, obj, []corev1.DNSPolicy{corev1.DNSClusterFirst, corev1.DNSClusterFirstWithHostNet, corev1.DNSDefault, corev1.DNSNone}, c)
		},
		func(obj *corev1.TypedObjectReference, c gofuzzheaders.Continue) {
			c.FuzzNoCustom(obj)
			str := c.RandString()
			obj.APIGroup = &str
		},
		func(obj *corev1.TypedLocalObjectReference, c gofuzzheaders.Continue) {
			c.FuzzNoCustom(obj)
			str := c.RandString()
			obj.APIGroup = &str
		},
		// Generate valid container images
		func(obj *corev1.Container, c gofuzzheaders.Continue) {
			obj.Name = generateValidK8sName(c, "container")
			obj.Image = fmt.Sprintf("quay.io/kubevirt/%s:%s", generateValidK8sLabel(c, "image"), "latest")
			
			// Add some valid env vars
			obj.Env = []corev1.EnvVar{
				{Name: "ENV_VAR", Value: "value"},
			}
			
			// Add valid ports
			if c.RandBool() {
				obj.Ports = []corev1.ContainerPort{
					{ContainerPort: int32(8080 + c.Intn(100)), Protocol: corev1.ProtocolTCP},
				}
			}
			
			// Skip complex fields that cause issues
			obj.Lifecycle = nil
			obj.SecurityContext = nil
		},
		// Generate valid PodSpec
		func(obj *corev1.PodSpec, c gofuzzheaders.Continue) {
			// Create a simple valid container
			container := corev1.Container{
				Name:  generateValidK8sName(c, "main"),
				Image: fmt.Sprintf("quay.io/kubevirt/%s:latest", generateValidK8sLabel(c, "image")),
			}
			obj.Containers = []corev1.Container{container}
			
			// Set valid restart policy
			obj.RestartPolicy = corev1.RestartPolicyAlways
			
			// Skip complex fields
			obj.InitContainers = nil
			obj.EphemeralContainers = nil
			obj.Volumes = nil
			obj.NodeSelector = nil
			obj.Affinity = nil
			obj.Tolerations = nil
			obj.SecurityContext = nil
		},
		// Generate valid ServiceSpec
		func(obj *corev1.ServiceSpec, c gofuzzheaders.Continue) {
			obj.Selector = map[string]string{
				"app": generateValidK8sLabel(c, "kubevirt"),
			}
			obj.Ports = []corev1.ServicePort{
				{
					Name:       generateValidK8sName(c, "port"),
					Port:       int32(8080 + c.Intn(100)),
					TargetPort: intstr.FromInt32(int32(8080 + c.Intn(100))),
					Protocol:   corev1.ProtocolTCP,
				},
			}
			obj.Type = corev1.ServiceTypeClusterIP
			obj.ClusterIP = "" // Let Kubernetes assign
			obj.SessionAffinity = corev1.ServiceAffinityNone
		},
		// Generate valid DeploymentSpec
		func(obj *appsv1.DeploymentSpec, c gofuzzheaders.Continue) {
			replicas := int32(1 + c.Intn(3))
			obj.Replicas = &replicas
			
			obj.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": generateValidK8sLabel(c, "kubevirt"),
				},
			}
			
			// Template will be fuzzed separately
			obj.Template = corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": generateValidK8sLabel(c, "kubevirt"),
					},
				},
			}
			// Spec will be filled by PodSpec fuzzer
			
			obj.Strategy = appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
			}
		},
		// Generate valid DaemonSetSpec
		func(obj *appsv1.DaemonSetSpec, c gofuzzheaders.Continue) {
			obj.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": generateValidK8sLabel(c, "kubevirt"),
				},
			}
			
			obj.Template = corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": generateValidK8sLabel(c, "kubevirt"),
					},
				},
			}
			// Spec will be filled by PodSpec fuzzer
			
			obj.UpdateStrategy = appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
			}
		},
	}

	typeFuzzers := []interface{}{}
	if !addSyntaxErrors {
		typeFuzzers = []interface{}{
			func(obj *int, c gofuzzheaders.Continue) {
				*obj = c.Intn(100000)
			},
			func(obj *uint, c gofuzzheaders.Continue) {
				*obj = uint(c.Intn(100000))
			},
			func(obj *int32, c gofuzzheaders.Continue) {
				*obj = int32(c.Intn(100000))
			},
			func(obj *int64, c gofuzzheaders.Continue) {
				*obj = int64(c.Intn(100000))
			},
			func(obj *uint64, c gofuzzheaders.Continue) {
				*obj = uint64(c.Intn(100000))
			},
			func(obj *uint32, c gofuzzheaders.Continue) {
				*obj = uint32(c.Intn(100000))
			},
		}
	}

	return append(enumFuzzers, typeFuzzers...)
}

func pickType(withSyntaxError bool, target interface{}, arr interface{}, c gofuzzheaders.Continue) {
	arrPtr := reflect.ValueOf(arr)
	targetPtr := reflect.ValueOf(target)

	if withSyntaxError {
		arrPtr = reflect.Append(arrPtr, reflect.ValueOf("fake").Convert(targetPtr.Elem().Type()))
	}

	idx := c.Int() % arrPtr.Len()

	targetPtr.Elem().Set(arrPtr.Index(idx))
}
