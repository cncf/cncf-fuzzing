package fuzzing

import (
	"fmt"

	admissioncel "k8s.io/apiserver/pkg/admission/plugin/cel"

	celgo "github.com/google/cel-go/cel"

	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/apiserver/pkg/cel/library"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

type fakeValidationCondition struct {
	Expression string
}

func (v *fakeValidationCondition) GetExpression() string {
	return v.Expression
}

func (v *fakeValidationCondition) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.BoolType}
}

func FuzzCelCompile(data []byte) int {
	f := fuzz.NewConsumer(data)
	expr, err := f.GetString()
	if err != nil {
		//fmt.Println(err)
		return 0
	}

	// Include the test library, which includes the test() function in the storage environment during test
	base := environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), true)
	extended, err := base.Extend(environment.VersionedOptions{
		IntroducedVersion: version.MajorMinor(1, 999),
		EnvOptions:        []celgo.EnvOption{library.Test()},
	})
	if err != nil {
		fmt.Println(err)
		return 0
	}
	compiler := admissioncel.NewCompiler(extended)
	
	options := admissioncel.OptionalVariableDeclarations{HasParams: true, HasAuthorizer: true}
	result := compiler.CompileCELExpression(&fakeValidationCondition{
		Expression: expr,
	}, options, environment.NewExpressions)
	if result.Error != nil {
		fmt.Sprintf("Got error: %s", result.Error)
		return 1
	}
	return 0
}
