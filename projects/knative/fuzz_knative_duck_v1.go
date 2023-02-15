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
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"knative.dev/pkg/apis"
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

var testConditions = apis.Conditions{{Type: apis.ConditionReady}, {Type: apis.ConditionSucceeded}}

func FuzzDuckV1RoundTripTypesToJSONExperimental(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, typeToTest int) {
		roundtrip.ExternalTypesViaJSON(data, typeToTest)
	})
}

var FuzzerFuncs = []interface{}{
	func(status *Status, c fuzz.Continue) error {
		_ = c.F.GenerateWithCustom(status) // fuzz the source
		// Clear the random fuzzed condition
		status.SetConditions(testConditions)
		err := roundtrip.FuzzConditions(status, c)
		return err
	},
}
