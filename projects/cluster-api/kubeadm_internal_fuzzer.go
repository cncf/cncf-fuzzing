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

package internal

import (
	"encoding/json"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	bootstrapv1 "sigs.k8s.io/cluster-api/bootstrap/kubeadm/api/v1beta1"
	controlplanev1 "sigs.k8s.io/cluster-api/controlplane/kubeadm/api/v1beta1"
	"sigs.k8s.io/yaml"
	"strings"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzMatchesMachineSpec(data []byte) int {
	f := fuzz.NewConsumer(data)
	machineConfigs := make(map[string]*bootstrapv1.KubeadmConfig)
	err := f.FuzzMap(&machineConfigs)
	if err != nil {
		return 0
	}
	kcp := &controlplanev1.KubeadmControlPlane{}
	err = f.GenerateStruct(kcp)
	if err != nil {
		return 0
	}
	infraConfigs, err := createInfraConfigs(f)
	if err != nil {
		return 0
	}
	_ = MatchesMachineSpec(infraConfigs, machineConfigs, kcp)
	return 1
}

func createInfraConfigs(f *fuzz.ConsumeFuzzer) (map[string]*unstructured.Unstructured, error) {
	numberOfKeys, err := f.GetInt()
	if err != nil {
		return nil, err
	}
	infraConfigs := make(map[string]*unstructured.Unstructured)
	for i := 0; i < numberOfKeys%10; i++ {
		key, err := f.GetString()
		if err != nil {
			return nil, err
		}
		valStr, err := f.GetString()
		if err != nil {
			return nil, err
		}
		val, err := UnstructuredForFuzzing(valStr)
		if err != nil {
			return nil, err
		}
		infraConfigs[key] = val
	}
	return infraConfigs, nil
}

func UnstructuredForFuzzing(text string) (*unstructured.Unstructured, error) {
	un := &unstructured.Unstructured{}
	var err error
	if strings.HasPrefix(text, "{") {
		err = json.Unmarshal([]byte(text), &un)
	} else {
		err = yaml.Unmarshal([]byte(text), &un)
	}
	if err != nil {
		return nil, err
	}
	return un, nil
}
