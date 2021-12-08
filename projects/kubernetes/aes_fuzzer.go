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
	stdlibAes "crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"reflect"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"k8s.io/apiserver/pkg/storage/value"
	aestransformer "k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

func FuzzAesRoundtrip(data []byte) int {
	f := fuzz.NewConsumer(data)
	cipherBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	if len(cipherBytes) == 0 {
		return 0
	}

	randBytes, err := f.GetBytes()
	if err != nil {
		return 0
	}
	if len(randBytes) == 0 {
		return 0
	}

	aesBlock, err := stdlibAes.NewCipher(cipherBytes)
	if err != nil {
		return 0
	}

	callGCMT, err := f.GetBool()
	if err != nil {
		return 0
	}
	if callGCMT {
		err = testGCMTTransformer(randBytes, aesBlock)
		if err != nil {
			panic(err)
		}
	} else {
		err = testCBCTransformer(randBytes, aesBlock)
	}

	return 1
}

func testGCMTTransformer(randBytes []byte, aesBlock cipher.Block) error {
	transformer := aestransformer.NewGCMTransformer(aesBlock)
	context := value.DefaultContext("")
	ciphertext, err := transformer.TransformToStorage(randBytes, context)
	if err != nil {
		return fmt.Errorf("TransformToStorage error = %v\n", err)
	}
	result, stale, err := transformer.TransformFromStorage(ciphertext, context)
	if err != nil {
		return fmt.Errorf("TransformFromStorage error = %v\n", err)
	}
	if stale {
		return fmt.Errorf("unexpected stale output\n")
	}
	if !reflect.DeepEqual(randBytes, result) {
		return fmt.Errorf("Round trip failed len=%d\noriginal:\n%s\nresult:\n%s\n", len(randBytes), hex.Dump(randBytes), hex.Dump(result))
	}
	return nil
}

func testCBCTransformer(randBytes []byte, aesBlock cipher.Block) error {
	transformer := aestransformer.NewCBCTransformer(aesBlock)
	context := value.DefaultContext("")
	ciphertext, err := transformer.TransformToStorage(randBytes, context)
	if err != nil {
		return fmt.Errorf("TransformToStorage error = %v\n", err)
	}
	result, stale, err := transformer.TransformFromStorage(ciphertext, context)
	if err != nil {
		return fmt.Errorf("TransformFromStorage error = %v\n", err)
	}
	if stale {
		return fmt.Errorf("unexpected stale output\n")
	}
	if !reflect.DeepEqual(randBytes, result) {
		return fmt.Errorf("Round trip failed len=%d\noriginal:\n%s\nresult:\n%s\n", len(randBytes), hex.Dump(randBytes), hex.Dump(result))
	}
	return nil
}
