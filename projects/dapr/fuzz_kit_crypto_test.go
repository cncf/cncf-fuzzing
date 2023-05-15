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

package crypto

import (
	"bytes"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzCryptoKeysAny(f *testing.F) {
	f.Fuzz(func(t *testing.T, raw []byte, contentTypeInt int) {
		var contentType string
		switch contentTypeInt % 3 {
		case 0:
			contentType = "application/json"
		case 1:
			contentType = "application/x-pem-file"
		case 2:
			contentType = "application/pkcs8"
		}
		k, err := ParseKey(raw, contentType)
		if err != nil {
			return
		}
		b, err := SerializeKey(k)
		if err != nil {
			return
		}
		var exported []byte
		err = k.Raw(&exported)
		if err != nil {
			return
		}
		if !bytes.Equal(exported, b) {
			panic(".Raw() issue")
		}
		if len(b) == 0 {
			return
		}
		if !bytes.Equal(raw, exported) {
			panic("Serialization issue")
		}
	})
}

func FuzzCryptoKeysJson(f *testing.F) {
	f.Fuzz(func(t *testing.T, raw []byte) {
		k, err := ParseKey(raw, "application/json")
		if err != nil {
			return
		}
		b, err := SerializeKey(k)
		if err != nil {
			return
		}
		var exported []byte
		err = k.Raw(&exported)
		if err != nil {
			return
		}
		if !bytes.Equal(exported, b) {
			panic(".Raw() issue")
		}
		if len(b) == 0 {
			return
		}
		if !bytes.Equal(raw, exported) {
			panic("Serialization issue")
		}
	})
}

func FuzzCryptoKeysRaw(f *testing.F) {
	f.Fuzz(func(t *testing.T, raw []byte) {
		k, err := ParseKey(raw, "")
		if err != nil {
			return
		}
		b, err := SerializeKey(k)
		if err != nil {
			return
		}
		var exported []byte
		err = k.Raw(&exported)
		if err != nil {
			return
		}
		if !bytes.Equal(exported, b) {
			panic(".Raw() issue")
		}
		if len(b) == 0 {
			return
		}
		if !bytes.Equal(raw, exported) {
			panic("Serialization issue")
		}
	})
}

func FuzzSymmetric(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		plaintext, err := ff.GetBytes()
		if err != nil {
			return
		}
		algorithm, err := ff.GetInt()
		if err != nil {
			return
		}
		keyData, err := ff.GetBytes()
		if err != nil {
			return
		}
		nonce, err := ff.GetBytes()
		if err != nil {
			return
		}
		associatedData, err := ff.GetBytes()
		if err != nil {
			return
		}
		key, err := jwk.ParseKey(keyData)
		if err != nil {
			return
		}
		algorithms := SupportedSymmetricAlgorithms()
		a := algorithms[algorithm%len(algorithms)]
		ciphertext, tag, err := EncryptSymmetric(plaintext, a, key, nonce, associatedData)
		if err != nil {
			return
		}

		gotPlaintext, err := DecryptSymmetric(ciphertext, a, key, nonce, tag, associatedData)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(plaintext, gotPlaintext) {
			panic("Plaintext incorrect")
		}
	})
}
