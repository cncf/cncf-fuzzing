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

package variables

import (
	"testing"
	"github.com/go-logr/logr"
	fuzz "github.com/AdamKorcz/go-fuzz-headers-1"
	kyverno "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/config"
	"github.com/kyverno/kyverno/pkg/engine/context"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
)

var (
	ConditionOperators = []kyverno.ConditionOperator{
		kyverno.ConditionOperator("Equal"),
		kyverno.ConditionOperator("Equals"),
		kyverno.ConditionOperator("NotEqual"),
		kyverno.ConditionOperator("NotEquals"),
		kyverno.ConditionOperator("In"),
		kyverno.ConditionOperator("AnyIn"),
		kyverno.ConditionOperator("AllIn"),
		kyverno.ConditionOperator("NotIn"),
		kyverno.ConditionOperator("AnyNotIn"),
		kyverno.ConditionOperator("AllNotIn"),
		kyverno.ConditionOperator("GreaterThanOrEquals"),
		kyverno.ConditionOperator("GreaterThan"),
		kyverno.ConditionOperator("LessThanOrEquals"),
		kyverno.ConditionOperator("LessThan"),
		kyverno.ConditionOperator("DurationGreaterThanOrEquals"),
		kyverno.ConditionOperator("DurationGreaterThan"),
		kyverno.ConditionOperator("DurationLessThanOrEquals"),
		kyverno.ConditionOperator("DurationLessThan"),
	}
)
func FuzzEvaluate(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		jsonData1, err := ff.GetBytes() 
		if err != nil {
			return
		}
		operator, err := ff.GetInt()
		if err != nil {
			return
		}
		jsonData2, err := ff.GetBytes() 
		if err != nil {
			return
		}
		o := ConditionOperators[operator%len(ConditionOperators)]
		cond := kyverno.Condition{
			RawKey: kyverno.ToJSON(jsonData1),
			Operator: o,
			RawValue: kyverno.ToJSON(jsonData2),
		}
		ctx := context.NewContext(jmespath.New(config.NewDefaultConfiguration(false)))
		_, _, _ = Evaluate(logr.Discard(), ctx, cond)
	})
}