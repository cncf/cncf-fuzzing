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
	"knative.dev/eventing/pkg/apis/messaging"

	gfh "github.com/AdaLogics/go-fuzz-headers"
)

func fuzzerFuncsGfh() []interface{} {
	return []interface{}{
		func(ch *Channel, c gfh.Continue) error {
			c.F.GenerateWithCustom(ch)
			if ch != nil {
				if ch.Annotations == nil {
					ch.Annotations = make(map[string]string)
				}
				ch.Annotations[messaging.SubscribableDuckVersionAnnotation] = "v1"
			}
			ch.Status.SetConditions(nil)

			ch.Status.InitializeConditions()
			return nil
		},
		func(imc *InMemoryChannel, c gfh.Continue) error {
			c.F.GenerateWithCustom(imc)
			if imc != nil {
				if imc.Annotations == nil {
					imc.Annotations = make(map[string]string)
				}
				imc.Annotations[messaging.SubscribableDuckVersionAnnotation] = "v1"
			}
			imc.Status.SetConditions(nil)

			imc.Status.InitializeConditions()
			return nil
		},
		func(s *SubscriptionStatus, c gfh.Continue) error {
			c.F.GenerateWithCustom(s)

			s.Status.SetConditions(nil)

			s.InitializeConditions()
			return nil
		},
	}
}
