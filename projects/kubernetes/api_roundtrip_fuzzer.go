package fuzzing

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/AdaLogics/go-fuzz-headers/bytesource"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	admissionregv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	apiserverinternalv1alpha1 "k8s.io/api/apiserverinternal/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	appsv1beta1 "k8s.io/api/apps/v1beta1"
	appsv1beta2 "k8s.io/api/apps/v1beta2"
	authenticationv1 "k8s.io/api/authentication/v1"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	authorizationv1 "k8s.io/api/authorization/v1"
	authorizationv1beta1 "k8s.io/api/authorization/v1beta1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	autoscalingv2beta1 "k8s.io/api/autoscaling/v2beta1"
	autoscalingv2beta2 "k8s.io/api/autoscaling/v2beta2"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	certificatesv1 "k8s.io/api/certificates/v1"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	coordinationv1 "k8s.io/api/coordination/v1"
	coordinationv1beta1 "k8s.io/api/coordination/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	discoveryv1beta1 "k8s.io/api/discovery/v1beta1"
	eventsv1 "k8s.io/api/events/v1"
	eventsv1beta1 "k8s.io/api/events/v1beta1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	flowcontrolv1alpha1 "k8s.io/api/flowcontrol/v1alpha1"
	flowcontrolv1beta1 "k8s.io/api/flowcontrol/v1beta1"
	imagepolicyv1alpha1 "k8s.io/api/imagepolicy/v1alpha1"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	nodev1 "k8s.io/api/node/v1"
	nodev1alpha1 "k8s.io/api/node/v1alpha1"
	nodev1beta1 "k8s.io/api/node/v1beta1"
	policyv1 "k8s.io/api/policy/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	rbacv1alpha1 "k8s.io/api/rbac/v1alpha1"
	rbacv1beta1 "k8s.io/api/rbac/v1beta1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	schedulingv1alpha1 "k8s.io/api/scheduling/v1alpha1"
	schedulingv1beta1 "k8s.io/api/scheduling/v1beta1"
	storagev1 "k8s.io/api/storage/v1"
	storagev1alpha1 "k8s.io/api/storage/v1alpha1"
	storagev1beta1 "k8s.io/api/storage/v1beta1"

	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	"k8s.io/apimachinery/pkg/api/apitesting/roundtrip"
	genericfuzzer "k8s.io/apimachinery/pkg/apis/meta/fuzzer"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var groups = []runtime.SchemeBuilder{
	admissionv1beta1.SchemeBuilder,
	admissionv1.SchemeBuilder,
	admissionregv1beta1.SchemeBuilder,
	admissionregv1.SchemeBuilder,
	apiserverinternalv1alpha1.SchemeBuilder,
	appsv1beta1.SchemeBuilder,
	appsv1beta2.SchemeBuilder,
	appsv1.SchemeBuilder,
	authenticationv1beta1.SchemeBuilder,
	authenticationv1.SchemeBuilder,
	authorizationv1beta1.SchemeBuilder,
	authorizationv1.SchemeBuilder,
	autoscalingv1.SchemeBuilder,
	autoscalingv2.SchemeBuilder,
	autoscalingv2beta1.SchemeBuilder,
	autoscalingv2beta2.SchemeBuilder,
	batchv1beta1.SchemeBuilder,
	batchv1.SchemeBuilder,
	certificatesv1.SchemeBuilder,
	certificatesv1beta1.SchemeBuilder,
	coordinationv1.SchemeBuilder,
	coordinationv1beta1.SchemeBuilder,
	corev1.SchemeBuilder,
	discoveryv1.SchemeBuilder,
	discoveryv1beta1.SchemeBuilder,
	eventsv1.SchemeBuilder,
	eventsv1beta1.SchemeBuilder,
	extensionsv1beta1.SchemeBuilder,
	flowcontrolv1alpha1.SchemeBuilder,
	flowcontrolv1beta1.SchemeBuilder,
	imagepolicyv1alpha1.SchemeBuilder,
	networkingv1.SchemeBuilder,
	networkingv1beta1.SchemeBuilder,
	nodev1.SchemeBuilder,
	nodev1alpha1.SchemeBuilder,
	nodev1beta1.SchemeBuilder,
	policyv1.SchemeBuilder,
	policyv1beta1.SchemeBuilder,
	rbacv1alpha1.SchemeBuilder,
	rbacv1beta1.SchemeBuilder,
	rbacv1.SchemeBuilder,
	schedulingv1alpha1.SchemeBuilder,
	schedulingv1beta1.SchemeBuilder,
	schedulingv1.SchemeBuilder,
	storagev1alpha1.SchemeBuilder,
	storagev1beta1.SchemeBuilder,
	storagev1.SchemeBuilder,
}

func init() {
	testing.Init()
}

func FuzzApiRoundtrip(data []byte) int {
	t := &testing.T{}
	f := fuzz.NewConsumer(data)

	seed := bytesource.New(data)

	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	for _, builder := range groups {
		err := builder.AddToScheme(scheme)
		if err != nil {
			return 0
		}
	}
	fuzzer := fuzzer.FuzzerFor(genericfuzzer.Funcs, seed, codecs)

	roundtrip.RoundTripExternalTypesAdaLogics(f, t, scheme, codecs, fuzzer, nil)
	return 1
}
