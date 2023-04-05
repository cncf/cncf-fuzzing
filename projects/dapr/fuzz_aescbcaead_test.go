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

package aescbcaead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	_ "crypto/hmac"
	"testing"
)

func FuzzAescbcaead(f *testing.F) {
	f.Fuzz(func(t *testing.T, key, dst, nonce, plaintext, additionalData []byte, keyType int){
		if len(nonce) != aes.BlockSize {
			return
		}
		var aead cipher.AEAD
		var err error
		switch keyType%4 {
		case 0:
			aead, err = NewAESCBC128SHA256(key)
			if err != nil {
				return
			}
		case 1:
			aead, err = NewAESCBC192SHA384(key)
			if err != nil {
				return
			}
		case 2:
			aead, err = NewAESCBC256SHA384(key)
			if err != nil {
				return
			}
		case 3:
			aead, err = NewAESCBC256SHA512(key)
			if err != nil {
				return
			}
		}

		gotCipherText := aead.Seal(dst, nonce, plaintext, additionalData)
		gotPlaintext, err := aead.Open(nil, nonce, gotCipherText, additionalData)
		if err != nil {
			return
		}
		if !bytes.Equal(plaintext, gotPlaintext) {
			panic("Not equal")
		}
	})
}
