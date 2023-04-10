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
	"testing"
)

func FuzzCryptoKeys(f *testing.F) {
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
			panic(err)
		}
		if !bytes.Equal(raw, b) {
			panic("Serialization issue")
		}
	})
}
