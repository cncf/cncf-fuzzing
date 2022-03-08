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

package utils

import (
	"github.com/blang/semver"
	bootstrapv1 "sigs.k8s.io/cluster-api/bootstrap/kubeadm/api/v1beta1"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)


func FuzzKubeadmTypesMarshalling(data []byte) int {
	if len(data)<10 {
		return 0
	}
	intType := int(data[0])
	switch intType%4 {
	case 0:
		return fuzzMarshalClusterConfigurationForVersion(data[1:])
	case 1:
		return fuzzMarshalClusterStatusForVersion(data[1:])
	case 2:
		return fuzzMarshalInitConfigurationForVersion(data[1:])
	case 3:
		return fuzzMarshalJoinConfigurationForVersion(data[1:])
	}
	return 1
}

func fuzzMarshalClusterConfigurationForVersion(data []byte) int {
	f := fuzz.NewConsumer(data)
	obj := &bootstrapv1.ClusterConfiguration{}
	err := f.GenerateStruct(obj)
	if err != nil {
		return 0
	}
	versionStr, err := f.GetString()
	if err != nil {
		return 0
	}
	version, err := semver.Parse(versionStr)
	if err != nil {
		return 0
	}
	_, _ = MarshalClusterConfigurationForVersion(obj, version)
	return 1
}

func fuzzMarshalClusterStatusForVersion(data []byte) int {
	f := fuzz.NewConsumer(data)
	obj := &bootstrapv1.ClusterStatus{}
	err := f.GenerateStruct(obj)
	if err != nil {
		return 0
	}
	versionStr, err := f.GetString()
	if err != nil {
		return 0
	}
	version, err := semver.Parse(versionStr)
	if err != nil {
		return 0
	}
	_, _ = MarshalClusterStatusForVersion(obj, version)
	return 1
}

func fuzzMarshalInitConfigurationForVersion(data []byte) int {
	f := fuzz.NewConsumer(data)
	obj := &bootstrapv1.InitConfiguration{}
	err := f.GenerateStruct(obj)
	if err != nil {
		return 0
	}
	versionStr, err := f.GetString()
	if err != nil {
		return 0
	}
	version, err := semver.Parse(versionStr)
	if err != nil {
		return 0
	}
	_, _ = MarshalInitConfigurationForVersion(obj, version)
	return 1
}

func fuzzMarshalJoinConfigurationForVersion(data []byte) int {
	f := fuzz.NewConsumer(data)
	obj := &bootstrapv1.JoinConfiguration{}
	err := f.GenerateStruct(obj)
	if err != nil {
		return 0
	}
	versionStr, err := f.GetString()
	if err != nil {
		return 0
	}
	version, err := semver.Parse(versionStr)
	if err != nil {
		return 0
	}
	_, _ = MarshalJoinConfigurationForVersion(obj, version)
	return 1
}

func FuzzUnmarshalClusterConfiguration(data []byte) int {
	_, _ = UnmarshalClusterConfiguration(string(data))
	return 1
}

func FuzzUnmarshalClusterStatus(data []byte) int {
	_, _ = UnmarshalClusterStatus(string(data))
	return 1
}