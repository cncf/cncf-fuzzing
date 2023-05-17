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
	_ "crypto/sha256"
	_ "crypto/sha512"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"runtime"
	"strings"
	"testing"
)

func catchPanics() {
	if r := recover(); r != nil {
		var err string
		switch r.(type) {
		case string:
			err = r.(string)
		case runtime.Error:
			err = r.(runtime.Error).Error()
		case error:
			err = r.(error).Error()
		}
		if strings.Contains(err, "invalid buffer overlap") {
			// known panic
			return
		} else {
			panic(err)
		}
	}
}

func FuzzAescbcaead(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)
		key, err := ff.GetBytes()
		if err != nil {
			return
		}
		nonce, err := ff.GetBytes()
		if err != nil {
			return
		}
		if len(nonce) != aes.BlockSize {
			return
		}
		plaintext, err := ff.GetBytes()
		if err != nil {
			return
		}
		keyType, err := ff.GetInt()
		if err != nil {
			return
		}
		additionalData, err := ff.GetBytes()
		if err != nil {
			return
		}
		defer catchPanics()
		var aead cipher.AEAD
		switch keyType % 4 {
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
		if aead == nil {
			return
		}

		gotCipherText := aead.Seal(nil, nonce, plaintext, additionalData)
		gotPlaintext, err := aead.Open(nil, nonce, gotCipherText, additionalData)
		if err != nil {
			return
		}
		if !bytes.Equal(plaintext, gotPlaintext) {
			panic("Not equal")
		}
	})
}
