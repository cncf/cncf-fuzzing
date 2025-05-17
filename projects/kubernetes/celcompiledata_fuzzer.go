// Copyright 2025 Shielder SpA
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
	"fmt"

	admissioncel "k8s.io/apiserver/pkg/admission/plugin/cel"
	validatingadmissionpolicy "k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/cel/environment"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzCelDataCompile(data []byte) int {
	f := fuzz.NewConsumer(data)

	expr, err := f.GetString()
	if err != nil {
		//fmt.Println("Error getting string:", err)
		return 0
	}

	compositionEnvTemplate, err := admissioncel.NewCompositionEnv(admissioncel.VariablesTypeName, environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), false))
	if err != nil {
		//fmt.Println("Error creating composition env:", err)
		return 0
	}
	compiler := admissioncel.NewCompositedCompilerFromTemplate(compositionEnvTemplate)
	options := admissioncel.OptionalVariableDeclarations{HasParams: true, HasAuthorizer: false}

	variable := &validatingadmissionpolicy.Variable{
		Name:       "foo",
		Expression: expr,
	}
	variables := []admissioncel.NamedExpressionAccessor{variable}
	compiler.CompileAndStoreVariables(variables, options, environment.StoredExpressions)

	// Use a bunch of fixed expressions
	tests := []struct {
		expression string
	}{
		{expression: "variables.foo > 1"},
		{expression: "variables.foo in [1, 2, 3]"},
		{expression: "variables.foo.startsWith('s')"},
		{expression: "variables.foo.matches('[0-9]+')"},
		{expression: "isURL(variables.foo)"},
	}
	for _, test := range tests {
		validation := &validatingadmissionpolicy.ValidationCondition{
			Expression: test.expression,
		}

		result := compiler.CompileCELExpression(validation, options, environment.StoredExpressions)
		// there's a bug in CompileCELExpression that returns nil error even if the expression is invalid
		if err := result.Error; err != nil {
			fmt.Printf("Got error: %s\n", result.Error)
			return 1
		}
	}

	return 0
}
