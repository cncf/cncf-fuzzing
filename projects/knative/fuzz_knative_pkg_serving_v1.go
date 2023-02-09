// Copyright 2023 the cncf-fuzzing authors
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

package v1

import (
	"github.com/AdamKorcz/kubefuzzing/pkg/roundtrip"
	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func init() {
	utilruntime.Must(AddToScheme(roundtrip.Scheme))
	roundtrip.AddFuncs(roundtrip.GenericFuzzerFuncs())
	roundtrip.AddFuncs(roundtrip.V1FuzzerFuncs())
	roundtrip.AddFuncs(roundtrip.V1beta1FuzzerFuncs())
	roundtrip.AddFuncs(roundtrip.FuzzerFuncs())
	roundtrip.AddFuncs(FuzzerFuncs)
	addKnownTypes(roundtrip.Scheme)
}

func FuzzServingV1RoundTripTypesToJSONExperimental(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, typeToTest int) {
		roundtrip.ExternalTypesViaJSON(data, typeToTest)
	})
}

var FuzzerFuncs = []interface{}{
	func(s *ConfigurationStatus, c fuzz.Continue) error {
		_ = c.F.GenerateWithCustom(s) // fuzz the status object

		// Clear the random fuzzed condition
		s.Status.SetConditions(nil)

		// Fuzz the known conditions except their type value
		s.InitializeConditions()
		err := roundtrip.FuzzConditions(&s.Status, c)
		return err
	},
	func(s *RevisionStatus, c fuzz.Continue) error {
		_ = c.F.GenerateWithCustom(s) // fuzz the status object

		// Clear the random fuzzed condition
		s.Status.SetConditions(nil)

		// Fuzz the known conditions except their type value
		s.InitializeConditions()
		err := roundtrip.FuzzConditions(&s.Status, c)
		return err
	},
	func(s *RouteStatus, c fuzz.Continue) error {
		_ = c.F.GenerateWithCustom(s) // fuzz the status object

		// Clear the random fuzzed condition
		s.Status.SetConditions(nil)

		// Fuzz the known conditions except their type value
		s.InitializeConditions()
		err := roundtrip.FuzzConditions(&s.Status, c)
		return err
	},
	func(s *ServiceStatus, c fuzz.Continue) error {
		_ = c.F.GenerateWithCustom(s) // fuzz the status object

		// Clear the random fuzzed condition
		s.Status.SetConditions(nil)

		// Fuzz the known conditions except their type value
		s.InitializeConditions()
		err := roundtrip.FuzzConditions(&s.Status, c)
		return err
	},
	func(ps *corev1.PodSpec, c fuzz.Continue) error {
		_ = c.F.GenerateWithCustom(ps)

		if len(ps.Containers) == 0 {
			// There must be at least 1 container.
			ps.Containers = append(ps.Containers, corev1.Container{})
			err := c.F.GenerateStruct(&ps.Containers[0])
			if err != nil {
				return err
			}
		}
		return nil
	},
}
