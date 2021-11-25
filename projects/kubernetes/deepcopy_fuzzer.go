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
	"reflect"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime"
)

func FuzzDeepCopy(data []byte) int {
	f := fuzz.NewConsumer(data)
	for _, version := range []schema.GroupVersion{{Group: "", Version: runtime.APIVersionInternal}, {Group: "", Version: "v1"}} {
		for kind := range legacyscheme.Scheme.KnownTypes(version) {
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
		panic("err")
	}

	prefuzzData := &bytes.Buffer{}
	if err := legacyscheme.Codecs.LegacyCodec(kind.GroupVersion()).Encode(item, prefuzzData); err != nil {
		panic(err)
	}

	err = f.GenerateStruct(itemCopy)
	if err != nil {
		return err
	}

	postfuzzData := &bytes.Buffer{}
	if err := legacyscheme.Codecs.LegacyCodec(kind.GroupVersion()).Encode(item, postfuzzData); err != nil {
		panic(err)
	}

	if !bytes.Equal(prefuzzData.Bytes(), postfuzzData.Bytes()) {
		panic(err)
	}
	return nil
}

