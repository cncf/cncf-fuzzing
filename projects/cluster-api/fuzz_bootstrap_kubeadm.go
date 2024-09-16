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
	"testing"
	"github.com/blang/semver/v4"
	bootstrapv1 "sigs.k8s.io/cluster-api/bootstrap/kubeadm/api/v1beta1"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)


func FuzzKubeadmTypesMarshalling(f *testing.F) {
	f.Fuzz(func (t *testing.T, data []byte, parserType int){
		switch parserType%4 {
		case 0:
			fuzzMarshalClusterConfigurationForVersion(data)
		case 1:
			fuzzMarshalClusterStatusForVersion(data)
		case 2:
			fuzzMarshalInitConfigurationForVersion(data)
		case 3:
			fuzzMarshalJoinConfigurationForVersion(data)
		}
		return
	})
}

func fuzzMarshalClusterConfigurationForVersion(data []byte) {
	f := fuzz.NewConsumer(data)
	obj := &bootstrapv1.ClusterConfiguration{}
	err := f.GenerateStruct(obj)
	if err != nil {
		return
	}
	versionStr, err := f.GetString()
	if err != nil {
		return
	}
	version, err := semver.Parse(versionStr)
	if err != nil {
		return
	}
	_, _ = MarshalClusterConfigurationForVersion(obj, version)
}

func fuzzMarshalClusterStatusForVersion(data []byte) {
	f := fuzz.NewConsumer(data)
	obj := &bootstrapv1.ClusterStatus{}
	err := f.GenerateStruct(obj)
	if err != nil {
		return
	}
	versionStr, err := f.GetString()
	if err != nil {
		return
	}
	version, err := semver.Parse(versionStr)
	if err != nil {
		return
	}
	MarshalClusterStatusForVersion(obj, version)
}

func fuzzMarshalInitConfigurationForVersion(data []byte) {
	f := fuzz.NewConsumer(data)
	obj := &bootstrapv1.InitConfiguration{}
	err := f.GenerateStruct(obj)
	if err != nil {
		return
	}
	versionStr, err := f.GetString()
	if err != nil {
		return
	}
	version, err := semver.Parse(versionStr)
	if err != nil {
		return
	}
	_, _ = MarshalInitConfigurationForVersion(&bootstrapv1.ClusterConfiguration{}, obj, version)
}

func fuzzMarshalJoinConfigurationForVersion(data []byte) {
	f := fuzz.NewConsumer(data)
	obj := &bootstrapv1.JoinConfiguration{}
	err := f.GenerateStruct(obj)
	if err != nil {
		return
	}
	versionStr, err := f.GetString()
	if err != nil {
		return
	}
	version, err := semver.Parse(versionStr)
	if err != nil {
		return
	}
	_, _ = MarshalJoinConfigurationForVersion(&bootstrapv1.ClusterConfiguration{}, obj, version)
}

func FuzzUnmarshalClusterConfiguration(f *testing.F) {
	f.Fuzz(func (t *testing.T, data string){
		_, _ = UnmarshalClusterConfiguration(data)
	})
}

func FuzzUnmarshalClusterStatus(f *testing.F) {
	f.Fuzz(func (t *testing.T, data string){
		_, _ = UnmarshalClusterStatus(data)
	})
}
