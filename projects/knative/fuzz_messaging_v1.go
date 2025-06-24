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
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	stdTesting "testing"

	"github.com/AdaLogics/go-fuzz-headers/bytesource"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang/protobuf/proto"
	fuzz "github.com/google/gofuzz"
	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metafuzzer "k8s.io/apimachinery/pkg/apis/meta/fuzzer"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"github.com/google/go-cmp/cmp"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	pkgfuzzer "knative.dev/pkg/apis/testing/fuzzer"

	"k8s.io/apimachinery/pkg/util/sets"
)

var (
	globalNonRoundTrippableTypes = sets.NewString(
		"ExportOptions",
		"GetOptions",
		// WatchEvent does not include kind and version and can only be deserialized
		// implicitly (if the caller expects the specific object). The watch call defines
		// the schema by content type, rather than via kind/version included in each
		// object.
		"WatchEvent",
		// ListOptions is now part of the meta group
		"ListOptions",
		// Delete options is only read in metav1
		"DeleteOptions",
	)

	fuzzerFuncs = fuzzer.MergeFuzzerFuncs(
		pkgfuzzer.Funcs,
		FuzzerFuncs,
	)

	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(AddToScheme(scheme))
}

func FuzzMessagingRoundTripTypesToJSON(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, typeToTest int) {
		t2 := &stdTesting.T{}

		ExternalTypesViaJSON(t2, data, typeToTest)
	})
}

func ExternalTypesViaJSON(t *stdTesting.T, data []byte, typeToTest int) {
	codecFactory := serializer.NewCodecFactory(scheme)

	seed := bytesource.New(data)
	f := fuzzer.FuzzerFor(
		fuzzer.MergeFuzzerFuncs(metafuzzer.Funcs, fuzzerFuncs),
		seed,
		codecFactory,
	)

	f.SkipFieldsWithPattern(regexp.MustCompile("DeprecatedGeneration"))

	kinds := scheme.AllKnownTypes()
	i := 0
	for gvk := range kinds {
		if gvk.Version == runtime.APIVersionInternal || globalNonRoundTrippableTypes.Has(gvk.Kind) {
			return
		}
		if i == typeToTest%len(kinds) {
			roundTripOfExternalType(t, scheme, codecFactory, f, gvk)
		}
		i++
	}
}

func roundTripOfExternalType(t *stdTesting.T, scheme *runtime.Scheme, codecFactory serializer.CodecFactory, fuzzer *fuzz.Fuzzer, externalGVK schema.GroupVersionKind) {
	object, err := scheme.New(externalGVK)
	if err != nil {
		t.Fatalf("Couldn't make a %v? %v", externalGVK, err)
	}
	typeAcc, err := apimeta.TypeAccessor(object)
	if err != nil {
		t.Fatalf("%q is not a TypeMeta and cannot be tested - add it to nonRoundTrippableInternalTypes: %v", externalGVK, err)
	}

	object = fuzzInternalObject(t, fuzzer, object)

	typeAcc.SetKind(externalGVK.Kind)
	typeAcc.SetAPIVersion(externalGVK.GroupVersion().String())

	roundTrip(t, scheme, json.NewSerializer(json.DefaultMetaFactory, scheme, scheme, false), object)

	// TODO remove this hack after we're past the intermediate steps
	roundTrip(t, scheme, protobuf.NewSerializer(scheme, scheme), object)
}

func fuzzInternalObject(t *stdTesting.T, fuzzer *fuzz.Fuzzer, object runtime.Object) runtime.Object {
	fuzzer.Fuzz(object)

	j, err := apimeta.TypeAccessor(object)
	if err != nil {
		t.Fatalf("Unexpected error %v for %#v", err, object)
	}
	j.SetKind("")
	j.SetAPIVersion("")

	return object
}

func roundTrip(t *stdTesting.T, scheme *runtime.Scheme, codec runtime.Codec, object runtime.Object) {
	printer := spew.ConfigState{DisableMethods: true}
	original := object

	// deep copy the original object
	object = object.DeepCopyObject()
	name := reflect.TypeOf(object).Elem().Name()
	if !apiequality.Semantic.DeepEqual(original, object) {
		fmt.Printf("%v: DeepCopy altered the object, diff: %v\n", name, cmp.Diff(original, object))
		fmt.Printf("%s\n", spew.Sdump(original))
		fmt.Printf("%s\n", spew.Sdump(object))
		panic("not equal")
	}

	// encode (serialize) the deep copy using the provided codec
	data, err := runtime.Encode(codec, object)
	if err != nil {
		return
	}

	// ensure that the deep copy is equal to the original; neither the deep
	// copy or conversion should alter the object
	// TODO eliminate this global
	if !apiequality.Semantic.DeepEqual(original, object) {
		t.Errorf("%v: encode altered the object, diff: %v", name, cmp.Diff(original, object))
		return
	}

	// encode (serialize) a second time to verify that it was not varying
	secondData, err := runtime.Encode(codec, object)
	if err != nil {
		if runtime.IsNotRegisteredError(err) {
			return
		} else {
			panic(fmt.Sprintf("%v: %v (%s)", name, err, printer.Sprintf("%#v", object)))
		}
	}

	// serialization to the wire must be stable to ensure that we don't write twice to the DB
	// when the object hasn't changed.
	if !bytes.Equal(data, secondData) {
		panic(fmt.Sprintf("%v: serialization is not stable: %s", name, printer.Sprintf("%#v", object)))
	}

	// decode (deserialize) the encoded data back into an object
	obj2, err := runtime.Decode(codec, data)
	if err != nil {
		fmt.Printf("%v: %v\nCodec: %#v\nData: %s\nSource: %#v\n", name, err, codec, dataAsString(data), printer.Sprintf("%#v", object))
		panic("failed")
	}

	// ensure that the object produced from decoding the encoded data is equal
	// to the original object
	if !apiequality.Semantic.DeepEqual(original, obj2) {
		panic(fmt.Sprintf("%v: diff: %v\nCodec: %#v\nSource:\n\n%#v\n\nEncoded:\n\n%s\n\nFinal:\n\n%#v\n", name, cmp.Diff(original, obj2), codec, printer.Sprintf("%#v", original), dataAsString(data), printer.Sprintf("%#v", obj2)))
	}

	// decode the encoded data into a new object (instead of letting the codec
	// create a new object)
	obj3 := reflect.New(reflect.TypeOf(object).Elem()).Interface().(runtime.Object)
	if err := runtime.DecodeInto(codec, data, obj3); err != nil {
		panic(fmt.Sprintf("%v: %v", name, err))
	}

	// special case for kinds which are internal and external at the same time (many in meta.k8s.io are). For those
	// runtime.DecodeInto above will return the external variant and set the APIVersion and kind, while the input
	// object might be internal. Hence, we clear those values for obj3 for that case to correctly compare.
	intAndExt, err := internalAndExternalKind(scheme, object)
	if err != nil {
		panic(fmt.Sprintf("%v: %v", name, err))
	}
	if intAndExt {
		typeAcc, err := apimeta.TypeAccessor(object)
		if err != nil {
			panic(fmt.Sprintf("%v: error accessing TypeMeta: %v\n", name, err))

		}
		if len(typeAcc.GetAPIVersion()) == 0 {
			typeAcc, err := apimeta.TypeAccessor(obj3)
			if err != nil {
				panic(fmt.Sprintf("%v: error accessing TypeMeta: %v", name, err))
			}
			typeAcc.SetAPIVersion("")
			typeAcc.SetKind("")
		}
	}

	// ensure that the new runtime object is equal to the original after being
	// decoded into
	if !apiequality.Semantic.DeepEqual(object, obj3) {
		panic(fmt.Sprintf("%v: diff: %v\nCodec: %#v", name, cmp.Diff(object, obj3), codec))
	}

	// do structure-preserving fuzzing of the deep-copied object. If it shares anything with the original,
	// the deep-copy was actually only a shallow copy. Then original and obj3 will be different after fuzzing.
	// NOTE: we use the encoding+decoding here as an alternative, guaranteed deep-copy to compare against.
	fuzzer.ValueFuzz(object)
	if !apiequality.Semantic.DeepEqual(original, obj3) {
		panic(fmt.Sprintf("%v: fuzzing a copy altered the original, diff: %v", name, cmp.Diff(original, obj3)))
	}
}

func internalAndExternalKind(scheme *runtime.Scheme, object runtime.Object) (bool, error) {
	kinds, _, err := scheme.ObjectKinds(object)
	if err != nil {
		return false, err
	}
	internal, external := false, false
	for _, k := range kinds {
		if k.Version == runtime.APIVersionInternal {
			internal = true
		} else {
			external = true
		}
	}
	return internal && external, nil
}

// dataAsString returns the given byte array as a string; handles detecting
// protocol buffers.
func dataAsString(data []byte) string {
	dataString := string(data)
	if !strings.HasPrefix(dataString, "{") {
		dataString = "\n" + hex.Dump(data)
		proto.NewBuffer(make([]byte, 0, 1024)).DebugPrint("decoded object", data)
	}
	return dataString
}
