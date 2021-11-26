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
	"k8s.io/kube-scheduler/config/v1beta2"
	config "k8s.io/kubernetes/pkg/scheduler/apis/config/v1beta2"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzSetDefaults_KubeSchedulerConfiguration(data []byte) int {
	c := &v1beta2.KubeSchedulerConfiguration{}
	f := fuzz.NewConsumer(data)
	err := f.GenerateStruct(c)
	if err != nil {
		return 0
	}
	config.SetDefaults_KubeSchedulerConfiguration(c)
	return 1
}
