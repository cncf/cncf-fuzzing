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
	"context"
	fuzz "github.com/AdaLogics/go-fuzz-headers"

	v1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsValidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/apis/audit"
	auditValidation "k8s.io/apiserver/pkg/apis/audit/validation"
	"k8s.io/kubernetes/pkg/apis/apiserverinternal"
	apiServerInternalValidation "k8s.io/kubernetes/pkg/apis/apiserverinternal/validation"
	"k8s.io/kubernetes/pkg/apis/apps"
	appsValidation "k8s.io/kubernetes/pkg/apis/apps/validation"
	"k8s.io/kubernetes/pkg/apis/autoscaling"
	autoscalingValidation "k8s.io/kubernetes/pkg/apis/autoscaling/validation"
	"k8s.io/kubernetes/pkg/apis/batch"
	batchValidation "k8s.io/kubernetes/pkg/apis/batch/validation"
	"k8s.io/kubernetes/pkg/apis/certificates"
	certificatesValidation "k8s.io/kubernetes/pkg/apis/certificates/validation"
	"k8s.io/kubernetes/pkg/apis/core"
	k8s_api_v1 "k8s.io/kubernetes/pkg/apis/core/v1"
	"k8s.io/kubernetes/pkg/apis/core/validation"
	"k8s.io/kubernetes/pkg/apis/policy"
	policyValidation "k8s.io/kubernetes/pkg/apis/policy/validation"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacValidation "k8s.io/kubernetes/pkg/apis/rbac/validation"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const maxFuzzers = 50

func FuzzAllValidation(data []byte) int {
	if len(data) < 10 {
		return 0
	}
	op := int(data[0]) % maxFuzzers
	inputData := data[1:]
	if op == 0 {
		return FuzzValidatePodCreate(inputData)
	} else if op == 1 {
		return FuzzValidatePodUpdate(inputData)
	} else if op == 2 {
		return FuzzValidatePodStatusUpdate(inputData)
	} else if op == 3 {
		return FuzzValidatePodEphemeralContainersUpdate(inputData)
	} else if op == 4 {
		return FuzzValidatePersistentVolumeUpdate(inputData)
	} else if op == 5 {
		return FuzzValidatePersistentVolumeClaimUpdate(inputData)
	} else if op == 6 {
		return FuzzValidateServiceCreate(inputData)
	} else if op == 7 {
		return FuzzValidateServiceUpdate(inputData)
	} else if op == 8 {
		return FuzzValidateEndpointsCreate(inputData)
	} else if op == 9 {
		return FuzzValidateNodeUpdate(inputData)
	} else if op == 10 {
		return FuzzValidateLimitRange(inputData)
	} else if op == 11 {
		return FuzzValidateStatefulSet(inputData)
	} else if op == 12 {
		return FuzzValidateStatefulSetUpdate(inputData)
	} else if op == 13 {
		return FuzzValidateDaemonSet(inputData)
	} else if op == 14 {
		return FuzzValidateDaemonSetUpdate(inputData)
	} else if op == 15 {
		return FuzzValidateDeployment(inputData)
	} else if op == 16 {
		return FuzzValidateDeploymentUpdate(inputData)
	} else if op == 17 {
		return FuzzValidateJob(inputData)
	} else if op == 18 {
		return FuzzValidateJobUpdate(inputData)
	} else if op == 19 {
		return FuzzValidateCronJobCreate(inputData)
	} else if op == 20 {
		return FuzzValidateCronJobUpdate(inputData)
	} else if op == 21 {
		return FuzzValidateScale(inputData)
	} else if op == 22 {
		return FuzzValidateHorizontalPodAutoscaler(inputData)
	} else if op == 23 {
		return FuzzValidateHorizontalPodAutoscalerUpdate(inputData)
	} else if op == 24 {
		return FuzzValidateDeployment(inputData)
	} else if op == 25 {
		return FuzzValidatePodDisruptionBudget(inputData)
	} else if op == 26 {
		return FuzzValidatePodDisruptionBudgetStatusUpdate(inputData)
	} else if op == 31 {
		return FuzzValidateCertificateSigningRequestCreate(inputData)
	} else if op == 32 {
		return FuzzValidateCertificateSigningRequestUpdate(inputData)
	} else if op == 33 {
		return FuzzValidateCertificateSigningRequestStatusUpdate(inputData)
	} else if op == 34 {
		return FuzzValidateCertificateSigningRequestApprovalUpdate(inputData)
	} else if op == 35 {
		return FuzzValidateCustomResourceDefinition(inputData)
	} else if op == 36 {
		return FuzzValidateStorageVersion(inputData)
	} else if op == 37 {
		return FuzzValidateStorageVersionName(inputData)
	} else if op == 38 {
		return FuzzValidateStorageVersionStatusUpdate(inputData)
	} else if op == 39 {
		return FuzzValidatePolicy(inputData)
	} else if op == 40 {
		return FuzzLoadPolicyFromBytes(inputData)
	} else if op == 41 {
		return FuzzValidateRoleUpdate(inputData)
	} else if op == 42 {
		return FuzzValidateClusterRoleUpdate(inputData)
	} else if op == 43 {
		return FuzzValidateRoleBindingUpdate(inputData)
	} else if op == 44 {
		return FuzzValidateClusterRoleBindingUpdate(inputData)
	} else if op == 45 {
		return FuzzCompactRules(inputData)
	} else if op == 46 {
		return FuzzValidateResourceQuotaSpec(inputData)
	} else if op == 47 {
		return FuzzValidateResourceQuotaUpdate(inputData)
	} else if op == 48 {
		FuzzValidateResourceQuotaStatusUpdate(inputData)
	} else if op == 49 {
		FuzzValidateServiceStatusUpdate(inputData)
	}
	return 0
}

//// Pod validation

func FuzzValidatePodCreate(data []byte) int {
	f := fuzz.NewConsumer(data)
	pod := &core.Pod{}
	err := f.GenerateStruct(pod)
	if err != nil {
		return 0
	}
	if errs := validation.ValidatePodCreate(pod, validation.PodValidationOptions{}); len(errs) > 0 {
		return 0
	}

	// Now test conversion
	v1Pod := &v1.Pod{}
	_ = k8s_api_v1.Convert_core_Pod_To_v1_Pod(pod, v1Pod, nil)
	return 1
}

func FuzzValidatePodUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	pod1 := &core.Pod{}
	err := f.GenerateStruct(pod1)
	if err != nil {
		return 0
	}
	pod2 := &core.Pod{}
	err = f.GenerateStruct(pod2)
	if err != nil {
		return 0
	}
	_ = validation.ValidatePodUpdate(pod1, pod2, validation.PodValidationOptions{})
	return 1
}

func FuzzValidatePodStatusUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	pod1 := &core.Pod{}
	err := f.GenerateStruct(pod1)
	if err != nil {
		return 0
	}
	pod2 := &core.Pod{}
	err = f.GenerateStruct(pod2)
	if err != nil {
		return 0
	}
	_ = validation.ValidatePodStatusUpdate(pod1, pod2, validation.PodValidationOptions{})
	return 1
}

func FuzzValidatePodEphemeralContainersUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	pod1 := &core.Pod{}
	err := f.GenerateStruct(pod1)
	if err != nil {
		return 0
	}
	pod2 := &core.Pod{}
	err = f.GenerateStruct(pod2)
	if err != nil {
		return 0
	}
	_ = validation.ValidatePodEphemeralContainersUpdate(pod1, pod2, validation.PodValidationOptions{})
	return 1
}

// Persistent volume validation

func FuzzValidatePersistentVolumeUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	pv1 := &core.PersistentVolume{}
	err := f.GenerateStruct(pv1)
	if err != nil {
		return 0
	}
	pv2 := &core.PersistentVolume{}
	err = f.GenerateStruct(pv2)
	if err != nil {
		return 0
	}
	opts := validation.PersistentVolumeSpecValidationOptions{}
	_ = validation.ValidatePersistentVolumeUpdate(pv1, pv2, opts)
	return 1
}

// Persistent Volume clain validation

func FuzzValidatePersistentVolumeClaimUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	pvc1 := &core.PersistentVolumeClaim{}
	err := f.GenerateStruct(pvc1)
	if err != nil {
		return 0
	}
	pvc2 := &core.PersistentVolumeClaim{}
	err = f.GenerateStruct(pvc2)
	if err != nil {
		return 0
	}
	opts := validation.PersistentVolumeClaimSpecValidationOptions{}
	_ = validation.ValidatePersistentVolumeClaimUpdate(pvc1, pvc2, opts)
	return 1
}

//// Service validation

func FuzzValidateServiceCreate(data []byte) int {
	service := &core.Service{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(service)
	if err != nil {
		return 0
	}
	_ = validation.ValidateServiceCreate(service)
	return 1
}

func FuzzValidateServiceUpdate(data []byte) int {
	service1 := &core.Service{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(service1)
	if err != nil {
		return 0
	}
	service2 := &core.Service{}
	err = f.GenerateStruct(service2)
	if err != nil {
		return 0
	}
	_ = validation.ValidateServiceUpdate(service1, service2)
	return 1
}

//// Endpoints validation

func FuzzValidateEndpointsCreate(data []byte) int {
	endpoints := &core.Endpoints{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(endpoints)
	if err != nil {
		return 0
	}
	_ = validation.ValidateEndpointsCreate(endpoints)
	return 1
}

// Node validation

func FuzzValidateNodeUpdate(data []byte) int {
	node1 := &core.Node{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(node1)
	if err != nil {
		return 0
	}
	node2 := &core.Node{}
	err = f.GenerateStruct(node2)
	if err != nil {
		return 0
	}
	_ = validation.ValidateNodeUpdate(node1, node2)
	return 1
}

// Limit Range validation

func FuzzValidateLimitRange(data []byte) int {
	limitRange := &core.LimitRange{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(limitRange)
	if err != nil {
		return 0
	}
	_ = validation.ValidateLimitRange(limitRange)
	return 1
}

// apps validation

func FuzzValidateStatefulSet(data []byte) int {
	//fmt.Println("Calling FuzzValidateStatefulSet")
	statefulset := &apps.StatefulSet{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(statefulset)
	if err != nil {
		return 0
	}
	if errs := appsValidation.ValidateStatefulSet(statefulset, validation.PodValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidateStatefulSetUpdate(data []byte) int {
	//fmt.Println("Calling FuzzValidateStatefulSetUpdate")
	f := fuzz.NewConsumer(data)
	statefulset1 := &apps.StatefulSet{}
	err := f.GenerateStruct(statefulset1)
	if err != nil {
		return 0
	}
	statefulset2 := &apps.StatefulSet{}
	err = f.GenerateStruct(statefulset2)
	if err != nil {
		return 0
	}
	opts := validation.PodValidationOptions{}
	err = f.GenerateStruct(&opts)
	if err != nil {
		return 0
	}
	if errs := appsValidation.ValidateStatefulSetUpdate(statefulset1, statefulset2, opts); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidateDaemonSet(data []byte) int {
	//fmt.Println("Calling FuzzValidateDaemonSet")
	daemonset := &apps.DaemonSet{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(daemonset)
	if err != nil {
		return 0
	}
	if errs := appsValidation.ValidateDaemonSet(daemonset, validation.PodValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidateDaemonSetUpdate(data []byte) int {
	//fmt.Println("Calling FuzzValidateDaemonSetUpdate")
	f := fuzz.NewConsumer(data)
	daemonset1 := &apps.DaemonSet{}
	err := f.GenerateStruct(daemonset1)
	if err != nil {
		return 0
	}
	daemonset2 := &apps.DaemonSet{}
	err = f.GenerateStruct(daemonset2)
	if err != nil {
		return 0
	}
	if errs := appsValidation.ValidateDaemonSetUpdate(daemonset1, daemonset2, validation.PodValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidateDeployment(data []byte) int {
	//fmt.Println("Calling FuzzValidateDeployment")
	deployment := &apps.Deployment{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(deployment)
	if err != nil {
		return 0
	}
	if errs := appsValidation.ValidateDeployment(deployment, validation.PodValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidateDeploymentUpdate(data []byte) int {
	//fmt.Println("Calling FuzzValidateDeploymentUpdate")
	f := fuzz.NewConsumer(data)
	deployment1 := &apps.Deployment{}
	err := f.GenerateStruct(deployment1)
	if err != nil {
		return 0
	}
	deployment2 := &apps.Deployment{}
	err = f.GenerateStruct(deployment2)
	if err != nil {
		return 0
	}
	if errs := appsValidation.ValidateDeploymentUpdate(deployment1, deployment2, validation.PodValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			//fmt.Println(err)
			_ = err
		}
		return 0
	}
	return 1
}

// batch validation

func FuzzValidateJob(data []byte) int {
	f := fuzz.NewConsumer(data)
	job := &batch.Job{}
	err := f.GenerateStruct(job)
	if err != nil {
		return 0
	}
	if errs := batchValidation.ValidateJob(job, batchValidation.JobValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidateJobUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	job1 := &batch.Job{}
	err := f.GenerateStruct(job1)
	if err != nil {
		return 0
	}
	job2 := &batch.Job{}
	err = f.GenerateStruct(job2)
	if err != nil {
		return 0
	}
	if errs := batchValidation.ValidateJobUpdate(job1, job2, batchValidation.JobValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidateCronJobCreate(data []byte) int {
	f := fuzz.NewConsumer(data)
	cronjob := &batch.CronJob{}
	err := f.GenerateStruct(cronjob)
	if err != nil {
		return 0
	}
	if errs := batchValidation.ValidateCronJobCreate(cronjob, validation.PodValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidateCronJobUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	cronjob1 := &batch.CronJob{}
	err := f.GenerateStruct(cronjob1)
	if err != nil {
		return 0
	}
	cronjob2 := &batch.CronJob{}
	err = f.GenerateStruct(cronjob2)
	if err != nil {
		return 0
	}
	if errs := batchValidation.ValidateCronJobUpdate(cronjob1, cronjob2, validation.PodValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

// autoscaling validation

func FuzzValidateScale(data []byte) int {
	f := fuzz.NewConsumer(data)
	scale := &autoscaling.Scale{}
	err := f.GenerateStruct(scale)
	if err != nil {
		return 0
	}
	if errs := autoscalingValidation.ValidateScale(scale); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidateHorizontalPodAutoscaler(data []byte) int {
	f := fuzz.NewConsumer(data)
	autoscaler := &autoscaling.HorizontalPodAutoscaler{}
	err := f.GenerateStruct(autoscaler)
	if err != nil {
		return 0
	}
	if errs := autoscalingValidation.ValidateHorizontalPodAutoscaler(autoscaler); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidateHorizontalPodAutoscalerUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	autoscaler1 := &autoscaling.HorizontalPodAutoscaler{}
	err := f.GenerateStruct(autoscaler1)
	if err != nil {
		return 0
	}
	autoscaler2 := &autoscaling.HorizontalPodAutoscaler{}
	err = f.GenerateStruct(autoscaler2)
	if err != nil {
		return 0
	}
	if errs := autoscalingValidation.ValidateHorizontalPodAutoscalerUpdate(autoscaler1, autoscaler2); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

// policy validation

func FuzzValidatePodDisruptionBudget(data []byte) int {
	f := fuzz.NewConsumer(data)
	pdb := &policy.PodDisruptionBudget{}
	err := f.GenerateStruct(pdb)
	if err != nil {
		return 0
	}
	if errs := policyValidation.ValidatePodDisruptionBudget(pdb, policyValidation.PodDisruptionBudgetValidationOptions{}); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

func FuzzValidatePodDisruptionBudgetStatusUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	status := policy.PodDisruptionBudgetStatus{}
	err := f.GenerateStruct(&status)
	if err != nil {
		return 0
	}
	oldStatus := policy.PodDisruptionBudgetStatus{}
	err = f.GenerateStruct(&oldStatus)
	if err != nil {
		return 0
	}
	if errs := policyValidation.ValidatePodDisruptionBudgetStatusUpdate(status, oldStatus, field.NewPath("status"), policy.SchemeGroupVersion); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	if errs := policyValidation.ValidatePodDisruptionBudgetStatusUpdate(status, oldStatus, field.NewPath("status"), policyv1beta1.SchemeGroupVersion); len(errs) > 0 {
		for _, err := range errs {
			_ = err
			//fmt.Println(err)
		}
		return 0
	}
	return 1
}

// certificates

func FuzzValidateCertificateSigningRequestCreate(data []byte) int {
	f := fuzz.NewConsumer(data)
	csr := &certificates.CertificateSigningRequest{}
	err := f.GenerateStruct(csr)
	if err != nil {
		return 0
	}
	//fmt.Println(csr)
	_ = certificatesValidation.ValidateCertificateSigningRequestCreate(csr)
	return 1
}

func FuzzValidateCertificateSigningRequestUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	csr1 := &certificates.CertificateSigningRequest{}
	err := f.GenerateStruct(csr1)
	if err != nil {
		return 0
	}
	//fmt.Println(csr1)
	csr2 := &certificates.CertificateSigningRequest{}
	err = f.GenerateStruct(csr2)
	if err != nil {
		return 0
	}
	//fmt.Println(csr2)
	_ = certificatesValidation.ValidateCertificateSigningRequestUpdate(csr1, csr2)
	return 1
}

func FuzzValidateCertificateSigningRequestStatusUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	csr1 := &certificates.CertificateSigningRequest{}
	err := f.GenerateStruct(csr1)
	if err != nil {
		return 0
	}
	//fmt.Println(csr1)
	csr2 := &certificates.CertificateSigningRequest{}
	err = f.GenerateStruct(csr2)
	if err != nil {
		return 0
	}
	//fmt.Println(csr2)
	_ = certificatesValidation.ValidateCertificateSigningRequestStatusUpdate(csr1, csr2)
	return 1
}

func FuzzValidateCertificateSigningRequestApprovalUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	csr1 := &certificates.CertificateSigningRequest{}
	err := f.GenerateStruct(csr1)
	if err != nil {
		return 0
	}
	//fmt.Println(csr1)
	csr2 := &certificates.CertificateSigningRequest{}
	err = f.GenerateStruct(csr1)
	if err != nil {
		return 0
	}
	//fmt.Println(csr2)
	_ = certificatesValidation.ValidateCertificateSigningRequestApprovalUpdate(csr1, csr2)
	return 1
}

// apiextensions-apiserver
func FuzzValidateCustomResourceDefinition(data []byte) int {
	f := fuzz.NewConsumer(data)
	crd := &apiextensions.CustomResourceDefinition{}
	err := f.GenerateStruct(crd)
	if err != nil {
		return 0
	}
	//fmt.Println(crd)
	_ = apiextensionsValidation.ValidateCustomResourceDefinition(context.Background(), crd)
	return 1
}

// apiserverinternal

func FuzzValidateStorageVersion(data []byte) int {
	f := fuzz.NewConsumer(data)
	sv := &apiserverinternal.StorageVersion{}
	err := f.GenerateStruct(sv)
	if err != nil {
		return 0
	}
	//fmt.Println(sv)
	_ = apiServerInternalValidation.ValidateStorageVersion(sv)
	return 1
}

func FuzzValidateStorageVersionName(data []byte) int {
	_ = apiServerInternalValidation.ValidateStorageVersionName(string(data), false)
	return 1
}

func FuzzValidateStorageVersionStatusUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	sv1 := &apiserverinternal.StorageVersion{}
	err := f.GenerateStruct(sv1)
	if err != nil {
		return 0
	}
	//fmt.Println(sv1)
	sv2 := &apiserverinternal.StorageVersion{}
	err = f.GenerateStruct(sv2)
	if err != nil {
		return 0
	}
	//fmt.Println(sv2)
	_ = apiServerInternalValidation.ValidateStorageVersionStatusUpdate(sv1, sv2)
	return 1
}

// apiserver audit

func FuzzValidatePolicy(data []byte) int {
	f := fuzz.NewConsumer(data)
	p := &audit.Policy{}
	err := f.GenerateStruct(p)
	if err != nil {
		return 0
	}
	//fmt.Println(p)
	_ = auditValidation.ValidatePolicy(p)
	return 1
}

// rbac validation
func FuzzValidateRoleUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	role1 := &rbac.Role{}
	err := f.GenerateStruct(role1)
	if err != nil {
		return 0
	}
	role2 := &rbac.Role{}
	err = f.GenerateStruct(role2)
	if err != nil {
		return 0
	}
	_ = rbacValidation.ValidateRoleUpdate(role1, role2)
	return 1
}

func FuzzValidateClusterRoleUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	clusterRole1 := &rbac.ClusterRole{}
	err := f.GenerateStruct(clusterRole1)
	if err != nil {
		return 0
	}
	clusterRole2 := &rbac.ClusterRole{}
	err = f.GenerateStruct(clusterRole2)
	if err != nil {
		return 0
	}
	_ = rbacValidation.ValidateClusterRoleUpdate(clusterRole1, clusterRole2, rbacValidation.ClusterRoleValidationOptions{})
	return 1
}

func FuzzValidateRoleBindingUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	roleBinding1 := &rbac.RoleBinding{}
	err := f.GenerateStruct(roleBinding1)
	if err != nil {
		return 0
	}
	roleBinding2 := &rbac.RoleBinding{}
	err = f.GenerateStruct(roleBinding2)
	if err != nil {
		return 0
	}
	_ = rbacValidation.ValidateRoleBindingUpdate(roleBinding1, roleBinding2)
	return 1
}

func FuzzValidateClusterRoleBindingUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	clusterRoleBinding1 := &rbac.ClusterRoleBinding{}
	err := f.GenerateStruct(clusterRoleBinding1)
	if err != nil {
		return 0
	}
	clusterRoleBinding2 := &rbac.ClusterRoleBinding{}
	err = f.GenerateStruct(clusterRoleBinding2)
	if err != nil {
		return 0
	}
	_ = rbacValidation.ValidateClusterRoleBindingUpdate(clusterRoleBinding1, clusterRoleBinding2)
	return 1
}

func FuzzCompactRules(data []byte) int {
	f := fuzz.NewConsumer(data)
	rules := make([]rbacv1.PolicyRule, 0)
	err := f.CreateSlice(&rules)
	if err != nil {
		return 0
	}
	_, _ = rbacregistryvalidation.CompactRules(rules)
	return 1
}

func FuzzValidateResourceQuotaSpec(data []byte) int {
	f := fuzz.NewConsumer(data)
	resourceQuotaSpec := &core.ResourceQuotaSpec{}
	err := f.GenerateStruct(resourceQuotaSpec)
	if err != nil {
		return 0
	}
	fld := &field.Path{}
	err = f.GenerateStruct(fld)
	if err != nil {
		return 0
	}
	_ = validation.ValidateResourceQuotaSpec(resourceQuotaSpec, fld)
	return 1
}

func FuzzValidateResourceQuotaUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	newResourceQuota := &core.ResourceQuota{}
	err := f.GenerateStruct(newResourceQuota)
	if err != nil {
		return 0
	}
	oldResourceQuota := &core.ResourceQuota{}
	err = f.GenerateStruct(oldResourceQuota)
	if err != nil {
		return 0
	}
	_ = validation.ValidateResourceQuotaUpdate(newResourceQuota, oldResourceQuota)
	return 1
}

func FuzzValidateResourceQuotaStatusUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	newResourceQuota := &core.ResourceQuota{}
	err := f.GenerateStruct(newResourceQuota)
	if err != nil {
		return 0
	}
	oldResourceQuota := &core.ResourceQuota{}
	err = f.GenerateStruct(oldResourceQuota)
	if err != nil {
		return 0
	}
	_ = validation.ValidateResourceQuotaStatusUpdate(newResourceQuota, oldResourceQuota)
	return 1
}

func FuzzValidateServiceStatusUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	service := &core.Service{}
	err := f.GenerateStruct(service)
	if err != nil {
		return 0
	}
	oldService := &core.Service{}
	err = f.GenerateStruct(oldService)
	if err != nil {
		return 0
	}
	_ = validation.ValidateServiceStatusUpdate(service, oldService)
	return 1
}
