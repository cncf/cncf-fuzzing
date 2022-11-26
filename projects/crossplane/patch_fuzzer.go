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

package v1

import (
	"errors"
	"github.com/crossplane/crossplane-runtime/pkg/resource/fake"
	pkgmetav1 "github.com/crossplane/crossplane/apis/pkg/meta/v1"
	pkgmetav1alpha1 "github.com/crossplane/crossplane/apis/pkg/meta/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

var (
	gvk          = &schema.GroupVersionKind{Version: "v1"}
	nonstrictOpt = json.SerializerOptions{Yaml: false, Pretty: false, Strict: false}
	fuzzScheme   = runtime.NewScheme()
	nonstrictSer = json.NewSerializerWithOptions(json.DefaultMetaFactory, fuzzScheme, fuzzScheme, nonstrictOpt)
)

func init() {
	if err := pkgmetav1alpha1.SchemeBuilder.AddToScheme(fuzzScheme); err != nil {
		panic(err)
	}
	if err := pkgmetav1.SchemeBuilder.AddToScheme(fuzzScheme); err != nil {
		panic(err)
	}
	if err := SchemeBuilder.AddToScheme(fuzzScheme); err != nil {
		panic(err)
	}
}

// Adds a type to the patch
func addType(p *Patch, i int) {
	chooseType := i % 5
	switch chooseType {
	case 0:
		p.Type = PatchTypeFromCompositeFieldPath
	case 1:
		p.Type = PatchTypePatchSet
	case 2:
		p.Type = PatchTypeToCompositeFieldPath
	case 3:
		p.Type = PatchTypeCombineFromComposite
	case 4:
		p.Type = PatchTypeCombineToComposite
	}
}

func FuzzPatchApply(data []byte) int {
	f := fuzz.NewConsumer(data)

	cp := &fake.Composite{}
	f.GenerateStruct(cp)

	cd := &fake.Composed{}
	f.GenerateStruct(cd)

	p := &Patch{}
	f.GenerateStruct(p)

	typeIndex, err := f.GetInt()
	if err != nil {
		return 0
	}
	addType(p, typeIndex)

	p.Apply(cp, cd)

	return 1
}

// Adds a type to the transform
func addTransformType(t *Transform, i int) error {
	chooseType := i % 4
	switch chooseType {
	case 0:
		t.Type = TransformTypeMap
		if t.Map == nil {
			return errors.New("Incorrect configuration")
		}
	case 1:
		t.Type = TransformTypeMath
		if t.Math == nil {
			return errors.New("Incorrect configuration")
		}
	case 2:
		t.Type = TransformTypeString
		if t.String == nil {
			return errors.New("Incorrect configuration")
		}
	case 3:
		t.Type = TransformTypeConvert
		if t.Convert == nil {
			return errors.New("Incorrect configuration")
		}
	}
	return nil
}

func FuzzTransform(data []byte) int {
	f := fuzz.NewConsumer(data)

	t := &Transform{}
	err := f.GenerateStruct(t)
	if err != nil {
		return 0
	}
	typeIndex, err := f.GetInt()
	if err != nil {
		return 0
	}
	err = addTransformType(t, typeIndex)
	if err != nil {
		return 0
	}

	i, err := f.GetString()
	if err != nil {
		return 0
	}

	t.Transform(i)
	return 1
}
