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
	"context"
	"errors"
	"fmt"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiServerValidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apiextensions-apiserver/pkg/registry/customresource/tableconvertor"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	metav1beta1 "k8s.io/apimachinery/pkg/apis/meta/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/util/jsonpath"
	kubeopenapispec "k8s.io/kube-openapi/pkg/validation/spec"
	"sync"
)

var scheme = runtime.NewScheme()
var fuzzInitter sync.Once

func setup() {
	if err := apiextensions.AddToScheme(scheme); err != nil {
		panic(err)
	}
}

func setup2() {
	// add internal and external types to scheme
	if err := apiextensions.AddToScheme(scheme); err != nil {
		panic(err)
	}
	if err := apiextensionsv1.AddToScheme(scheme); err != nil {
		panic(err)
	}
}

func FuzzApiServerRoundtrip(data []byte) int {
	err := apiextensionsRoundtrip(data)
	if err != nil {
		panic(err)
	}
	return 1
}

// TestRoundTrip checks the conversion to go-openapi types.
// internal -> go-openapi -> JSON -> external -> internal.
// Similar to https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/validation/validation_test.go#L37
func apiextensionsRoundtrip(data []byte) error {
	f := fuzz.NewConsumer(data)
	for i := 0; i < 20; i++ {
		// fuzz internal types
		internal := &apiextensions.JSONSchemaProps{}
		err := f.GenerateStruct(&internal)
		if err != nil {
			return nil
		}

		// internal -> go-openapi
		openAPITypes := &kubeopenapispec.Schema{}
		if err := apiServerValidation.ConvertJSONSchemaProps(internal, openAPITypes); err != nil {
			return err
		}

		// go-openapi -> JSON
		openAPIJSON, err := json.Marshal(openAPITypes)
		if err != nil {
			return err
		}

		// JSON -> in-memory JSON => convertNullTypeToNullable => JSON
		var j interface{}
		if err := json.Unmarshal(openAPIJSON, &j); err != nil {
			return err
		}
		j = stripIntOrStringType(j)
		openAPIJSON, err = json.Marshal(j)
		if err != nil {
			return err
		}

		// JSON -> external
		external := &apiextensionsv1.JSONSchemaProps{}
		if err := json.Unmarshal(openAPIJSON, external); err != nil {
			return err
		}

		// external -> internal
		internalRoundTripped := &apiextensions.JSONSchemaProps{}
		if err := scheme.Convert(external, internalRoundTripped, nil); err != nil {
			return err
		}

		if !apiequality.Semantic.DeepEqual(internal, internalRoundTripped) {
			return errors.New(fmt.Sprintf("%d: expected\n\t%#v, got \n\t%#v", i, internal, internalRoundTripped))
		}
		fmt.Println("Ran full fuzzer")
	}
	return nil
}

func stripIntOrStringType(x interface{}) interface{} {
	switch x := x.(type) {
	case map[string]interface{}:
		if t, found := x["type"]; found {
			switch t := t.(type) {
			case []interface{}:
				if len(t) == 2 && t[0] == "integer" && t[1] == "string" && x["x-kubernetes-int-or-string"] == true {
					delete(x, "type")
				}
			}
		}
		for k := range x {
			x[k] = stripIntOrStringType(x[k])
		}
		return x
	case []interface{}:
		for i := range x {
			x[i] = stripIntOrStringType(x[i])
		}
		return x
	default:
		return x
	}
}

func newJSONPath(name string, jsonPathExpression string) *jsonpath.JSONPath {
	jp := jsonpath.New(name)
	_ = jp.Parse(jsonPathExpression)
	return jp
}

func FuzzConvertToTable(data []byte) int {
	f := fuzz.NewConsumer(data)
	crdColumns := createCRCDs(f)
	if len(crdColumns) == 0 {
		return 0
	}
	c, err := tableconvertor.New(crdColumns)
	if err != nil {
		return 0
	}
	o, err := getObject(f)
	if err != nil {
		return 0
	}
	table, err := c.ConvertToTable(context.Background(), o, nil)
	if err != nil {
		return 0
	}
	_ = table
	return 1
}

func createCRCDs(f *fuzz.ConsumeFuzzer) []apiextensionsv1.CustomResourceColumnDefinition {
	crcds := make([]apiextensionsv1.CustomResourceColumnDefinition, 0)
	noOfCRCDs, err := f.GetInt()
	if err != nil {
		return crcds
	}
	for i := 0; i < noOfCRCDs%20; i++ {
		crcd := apiextensionsv1.CustomResourceColumnDefinition{}
		err = f.GenerateStruct(&crcd)
		if err != nil {
			return crcds
		}
		crcds = append(crcds, crcd)
	}
	return crcds
}

func getObject(f *fuzz.ConsumeFuzzer) (runtime.Object, error) {
	emptyObject := &unstructured.Unstructured{}
	typeOfObject, err := f.GetInt()
	if err != nil {
		return emptyObject, err
	}
	if typeOfObject%3 == 0 {
		o := &metav1beta1.PartialObjectMetadata{}
		err = f.GenerateStruct(o)
		if err != nil {
			return emptyObject, err
		}
		return runtime.Object(o), nil
	}
	if typeOfObject%3 == 1 {
		o := &metav1beta1.PartialObjectMetadataList{}
		err = f.GenerateStruct(o)
		if err != nil {
			return emptyObject, err
		}
		return runtime.Object(o), nil
	}
	if typeOfObject%3 == 2 {
		o := &unstructured.Unstructured{}
		err = f.GenerateStruct(o)
		if err != nil {
			return emptyObject, err
		}
		return runtime.Object(o), nil
	}
	return emptyObject, fmt.Errorf("Could not create object")
}
