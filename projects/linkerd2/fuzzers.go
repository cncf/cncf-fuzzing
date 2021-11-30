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
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/linkerd/linkerd2/pkg/healthcheck"
	"github.com/linkerd/linkerd2/pkg/util"
	corev1 "k8s.io/api/core/v1"
)

func FuzzParsePorts(data []byte) int {
	_, _ = util.ParsePorts(string(data))
	return 1
}

func FuzzParseContainerOpaquePorts(data []byte) int {
	f := fuzz.NewConsumer(data)

	qtyOfContainers, err := f.GetInt()
	if err != nil {
		return 0
	}

	containers := make([]corev1.Container, 0)
	for i := 0; i < qtyOfContainers%20; i++ {
		newContainer := corev1.Container{}
		err = f.GenerateStruct(&newContainer)
		if err != nil {
			return 0
		}
		containers = append(containers, newContainer)
	}
	override, err := f.GetString()
	if err != nil {
		return 0
	}
	_ = util.ParseContainerOpaquePorts(override, containers)
	return 1
}

func FuzzHealthCheck(data []byte) int {
	f := fuzz.NewConsumer(data)
	options := &healthcheck.Options{}
	err := f.GenerateStruct(options)
	if err != nil {
		return 0
	}
	_ = healthcheck.NewHealthChecker([]healthcheck.CategoryID{healthcheck.KubernetesAPIChecks}, options)
	return 1
}
