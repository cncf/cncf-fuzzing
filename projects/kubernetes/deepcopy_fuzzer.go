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
	"bytes"
	"errors"
	"reflect"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
)

// FuzzDeepCopy implements a fuzzer for the logic defined in:
// https://github.com/kubernetes/kubernetes/blob/master/pkg/api/testing/copy_test.go
func FuzzDeepCopy(data []byte) int {
	f := fuzz.NewConsumer(data)

	// get groupversion
	versionIndex, err := f.GetInt()
	if err != nil {
		return 0
	}
	groupVersions := []schema.GroupVersion{{Group: "", Version: runtime.APIVersionInternal}, {Group: "", Version: "v1"}}
	version := groupVersions[versionIndex%len(groupVersions)]

	// pick a kind and do the deepcopy test
	knownTypes := legacyscheme.Scheme.KnownTypes(version)
	kindIndex, err := f.GetInt()
	if err != nil {
		return 0
	}
	kindIndex = kindIndex % len(knownTypes)
	i := 0
	for kind := range knownTypes {
		if i == kindIndex {
			doDeepCopyTest(version.WithKind(kind), f)
		}
	}
	return 1
}

func doDeepCopyTest(kind schema.GroupVersionKind, f *fuzz.ConsumeFuzzer) error {
	item, err := legacyscheme.Scheme.New(kind)
	if err != nil {
		return err
	}
	err = f.GenerateStruct(item)
	if err != nil {
		return err
	}
	itemCopy := item.DeepCopyObject()
	if !reflect.DeepEqual(item, itemCopy) {
		panic("Items should be equal but are not.")
	}

	prefuzzData := &bytes.Buffer{}
	if err := legacyscheme.Codecs.LegacyCodec(kind.GroupVersion()).Encode(item, prefuzzData); err != nil {
		return errors.New("Could not encode original")
	}

	err = f.GenerateStruct(itemCopy)
	if err != nil {
		return err
	}

	postfuzzData := &bytes.Buffer{}
	if err := legacyscheme.Codecs.LegacyCodec(kind.GroupVersion()).Encode(item, postfuzzData); err != nil {
		return errors.New("Could not encode the copy")
	}

	if !bytes.Equal(prefuzzData.Bytes(), postfuzzData.Bytes()) {
		panic("Bytes should be equal but are not")
	}
	return nil
}
