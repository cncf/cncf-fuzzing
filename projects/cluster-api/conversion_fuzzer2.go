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

package fuzz

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"sigs.k8s.io/controller-runtime/pkg/conversion"

	"sigs.k8s.io/cluster-api/api/v1alpha3"
	"sigs.k8s.io/cluster-api/api/v1alpha4"
	"sigs.k8s.io/cluster-api/api/v1beta1"
	bootstrapv1alpha3 "sigs.k8s.io/cluster-api/bootstrap/kubeadm/api/v1alpha3"
	bootstrapv1alpha4 "sigs.k8s.io/cluster-api/bootstrap/kubeadm/api/v1alpha4"
	bootstrapv1 "sigs.k8s.io/cluster-api/bootstrap/kubeadm/api/v1beta1"
	"sigs.k8s.io/cluster-api/bootstrap/kubeadm/types/upstreamv1beta1"
	"sigs.k8s.io/cluster-api/bootstrap/kubeadm/types/upstreamv1beta2"
	"sigs.k8s.io/cluster-api/bootstrap/kubeadm/types/upstreamv1beta3"
	controlplanev1alpha3 "sigs.k8s.io/cluster-api/controlplane/kubeadm/api/v1alpha3"
	controlplanev1alpha4 "sigs.k8s.io/cluster-api/controlplane/kubeadm/api/v1alpha4"
	controlplanev1 "sigs.k8s.io/cluster-api/controlplane/kubeadm/api/v1beta1"
)

type FuzzTestFuncInput struct {
	Hub   conversion.Hub
	Spoke conversion.Convertible
}

func createInput(objType1, objType2 int) FuzzTestFuncInput {
	input := &FuzzTestFuncInput{}
	switch objType1 {
	case 0:
		input.Hub = &v1beta1.Cluster{}
	case 1:
		input.Hub = &v1beta1.ClusterList{}
	case 2:
		input.Hub = &v1beta1.Machine{}
	case 3:
		input.Hub = &v1beta1.MachineList{}
	case 4:
		input.Hub = &v1beta1.MachineSet{}
	case 5:
		input.Hub = &v1beta1.MachineSetList{}
	case 6:
		input.Hub = &v1beta1.MachineDeployment{}
	case 7:
		input.Hub = &v1beta1.MachineDeploymentList{}
	case 8:
		input.Hub = &v1beta1.MachineHealthCheck{}
	case 9:
		input.Hub = &v1beta1.MachineHealthCheckList{}
	case 10:
		input.Hub = &bootstrapv1.ClusterConfiguration{}
	case 11:
		input.Hub = &bootstrapv1.ClusterStatus{}
	case 12:
		input.Hub = &bootstrapv1.InitConfiguration{}
	case 13:
		input.Hub = &bootstrapv1.JoinConfiguration{}
	case 14:
		input.Hub = &controlplanev1.KubeadmControlPlane{}
	}

	switch objType2 {
	case 0:
		input.Spoke = &v1alpha3.Cluster{}
	case 1:
		input.Spoke = &v1alpha3.ClusterList{}
	case 2:
		input.Spoke = &v1alpha3.Cluster{}
	case 3:
		input.Spoke = &v1alpha3.ClusterList{}
	case 4:
		input.Spoke = &v1alpha3.Machine{}
	case 5:
		input.Spoke = &v1alpha3.MachineList{}
	case 6:
		input.Spoke = &v1alpha3.MachineSet{}
	case 7:
		input.Spoke = &v1alpha3.MachineSetList{}
	case 8:
		input.Spoke = &v1alpha3.MachineDeployment{}
	case 9:
		input.Spoke = &v1alpha3.MachineDeploymentList{}
	case 10:
		input.Spoke = &v1alpha3.MachineHealthCheck{}
	case 11:
		input.Spoke = &v1alpha3.MachineHealthCheckList{}
	case 12:
		input.Spoke = &v1alpha4.Cluster{}
	case 13:
		input.Spoke = &v1alpha4.ClusterList{}
	case 14:
		input.Spoke = &v1alpha4.ClusterClass{}
	case 15:
		input.Spoke = &v1alpha4.ClusterClassList{}
	case 16:
		input.Spoke = &v1alpha4.Machine{}
	case 17:
		input.Spoke = &v1alpha4.MachineList{}
	case 18:
		input.Spoke = &v1alpha4.MachineSetList{}
	case 19:
		input.Spoke = &v1alpha4.MachineDeployment{}
	case 20:
		input.Spoke = &v1alpha4.MachineDeploymentList{}
	case 21:
		input.Spoke = &v1alpha4.MachineHealthCheck{}
	case 22:
		input.Spoke = &v1alpha4.MachineHealthCheckList{}
	case 23:
		input.Spoke = &bootstrapv1alpha3.KubeadmConfig{}
	case 24:
		input.Spoke = &bootstrapv1alpha3.KubeadmConfigTemplate{}
	case 25:
		input.Spoke = &bootstrapv1alpha4.KubeadmConfig{}
	case 26:
		input.Spoke = &upstreamv1beta2.ClusterConfiguration{}
	case 27:
		input.Spoke = &upstreamv1beta2.ClusterStatus{}
	case 28:
		input.Spoke = &upstreamv1beta2.InitConfiguration{}
	case 29:
		input.Spoke = &upstreamv1beta2.JoinConfiguration{}
	case 30:
		input.Spoke = &upstreamv1beta1.ClusterConfiguration{}
	case 31:
		input.Spoke = &upstreamv1beta1.ClusterStatus{}
	case 32:
		input.Spoke = &upstreamv1beta1.InitConfiguration{}
	case 33:
		input.Spoke = &upstreamv1beta1.JoinConfiguration{}
	case 34:
		input.Spoke = &upstreamv1beta3.ClusterConfiguration{}
	case 35:
		input.Spoke = &upstreamv1beta3.InitConfiguration{}
	case 36:
		input.Spoke = &upstreamv1beta3.JoinConfiguration{}
	case 37:
		input.Spoke = &controlplanev1alpha3.KubeadmControlPlane{}
	case 38:
		input.Spoke = &controlplanev1alpha4.KubeadmControlPlane{}
	case 39:
		input.Spoke = &controlplanev1alpha4.KubeadmControlPlaneTemplate{}
	}
	return *input
}

// Calls ConvertFrom() and ConvertTo() with valid
// conversion.Convertible and conversion.Hub
func FuzzConversionOfAllTypes(data []byte) int {
	f := fuzz.NewConsumer(data)
	objType1, err := f.GetInt()
	if err != nil {
		return 0
	}

	objType2, err := f.GetInt()
	if err != nil {
		return 0
	}
	input := createInput(objType1%15, objType2%40)

	err = f.GenerateStruct(input.Hub)
	if err != nil {
		return 0
	}

	err = f.GenerateStruct(input.Spoke)
	if err != nil {
		return 0
	}

	input.Spoke.ConvertTo(input.Hub)
	input.Spoke.ConvertFrom(input.Hub)
	return 1
}
