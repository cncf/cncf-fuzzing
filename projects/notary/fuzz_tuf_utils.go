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

package utils

import (
	"bytes"
	"crypto/rsa"
	"github.com/theupdateframework/notary/tuf/data"
	"testing"
)

var (
	keys = map[int]string{
		0: "ed25519",
		1: "ECDA",
		2: "rsa",
	}
)

func FuzzParsePEMPrivateKey(f *testing.F) {
	f.Fuzz(func(t *testing.T, keyBytes []byte, keyType int, bits int64, passphrase string, usePassPhrase bool) {

		var key data.PrivateKey
		var edPEM []byte
		var err error
		switch keys[keyType%len(keys)] {
		case "ed25519":
			key, err = GenerateED25519Key(bytes.NewReader(keyBytes))
			if err != nil {
				t.Skip()
			}
		case "ECDA":
			key, err = GenerateECDSAKey(bytes.NewReader(keyBytes))
			if err != nil {
				t.Skip()
			}
		case "rsa":
			rsaKey, err := rsa.GenerateKey(bytes.NewReader(keyBytes), int(bits))
			if err != nil {
				t.Skip()
			}
			err = rsaKey.Validate()
			if err != nil {
				t.Skip()
			}
			key, err = RSAToPrivateKey(rsaKey)
			if err != nil {
				t.Fatal(err)
			}
		}

		if usePassPhrase {
			edPEM, err = ConvertPrivateKeyToPKCS8(key, data.CanonicalRootRole, "", passphrase)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			edPEM, err = ConvertPrivateKeyToPKCS8(key, data.CanonicalRootRole, "", "")
			if err != nil {
				t.Fatal(err)
			}
		}

		role, _, err := ExtractPrivateKeyAttributes(edPEM)
		if err != nil {
			t.Fatal(err)
		}
		if role != "root" {
			t.Fatal("role should be root")
		}

		if usePassPhrase {
			_, _ = ParsePEMPrivateKey(edPEM, passphrase)
		} else {
			_, _ = ParsePEMPrivateKey(edPEM, "")
		}
	})
}
