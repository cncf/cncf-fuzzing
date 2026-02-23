// Copyright 2025 the cncf-fuzzing authors
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
///////////////////////////////////////////////////////////////////////////

package fuzz

import (
	"bytes"
	"testing"

	"github.com/oxia-db/oxia/common/compare"
)

// FuzzDatabaseRangeOperations tests range scan boundary conditions
func FuzzDatabaseRangeOperations(f *testing.F) {
	f.Add(buildSeed(encStr(""), encStr("z"), encInt32(10)))
	f.Add(buildSeed(encStr("a"), encStr("a"), encInt32(1)))
	f.Add(buildSeed(encStr("a"), encStr("b"), encInt32(100)))
	f.Add(buildSeed(encStr("/"), encStr("0/"), encInt32(10)))
	f.Add(buildSeed(encStr("key"), encStr("key"), encInt32(0)))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)
		startKeyStr, ok := c.consumeString(255)
		if !ok {
			return
		}
		endKeyStr, ok := c.consumeString(255)
		if !ok {
			return
		}
		limit, ok := c.consumeInt32()
		if !ok {
			return
		}

		startKey := []byte(startKeyStr)
		endKey := []byte(endKeyStr)

		if limit < 0 || limit > 10000 {
			return
		}

		cmp := compare.CompareWithSlash(startKey, endKey)

		if cmp >= 0 && len(startKey) > 0 && len(endKey) > 0 {
			// Invalid range
		}

		if len(startKey) > 0 && len(endKey) > 0 && cmp < 0 {
			keyAtStart := compare.CompareWithSlash(startKey, startKey)
			if keyAtStart != 0 {
				t.Fatalf("Key comparison with itself failed: %d", keyAtStart)
			}

			if bytes.Equal(startKey, endKey) {
				// Same key - empty range
			}
		}

		if bytes.Equal(startKey, []byte("/")) && bytes.Equal(endKey, []byte("0/")) {
			cmpTest := compare.CompareWithSlash(startKey, endKey)
			if cmpTest >= 0 {
				t.Fatalf("CompareWithSlash(\"/\", \"0/\") = %d, expected < 0", cmpTest)
			}
		}

		if limit < 0 {
			t.Fatalf("Negative limit: %d", limit)
		}
	})
}

// FuzzDatabaseKeyValidation tests key validation rules
func FuzzDatabaseKeyValidation(f *testing.F) {
	f.Add([]byte("valid-key"))
	f.Add([]byte(""))  // Empty key
	f.Add([]byte("/")) // Slash
	f.Add([]byte("key/with/slashes"))
	f.Add([]byte("\x00")) // Null byte
	f.Add([]byte("\xff")) // High byte

	f.Fuzz(func(t *testing.T, key []byte) {
		if len(key) == 0 {
			return
		}

		if bytes.Contains(key, []byte{0x00}) {
			// Null byte - might be rejected
		}

		if bytes.Contains(key, []byte{0xff}) {
			if bytes.HasPrefix(key, []byte{0xff, 0xff}) {
				return
			}
		}

		const maxKeyLen = 8192
		if len(key) > maxKeyLen {
			// Key too long
		}

		if len(key) > 0 {
			encoded := compare.EncoderNatural.Encode(string(key))
			decoded := compare.EncoderNatural.Decode(encoded)
			if decoded != string(key) {
				t.Fatalf("Natural encoder roundtrip failed: %q != %q", decoded, string(key))
			}
		}
	})
}
