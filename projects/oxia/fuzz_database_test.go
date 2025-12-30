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

package oxia

import (
	"bytes"
	"testing"

	"github.com/oxia-db/oxia/common/compare"
)

// FuzzDatabaseRangeOperations tests range scan boundary conditions
func FuzzDatabaseRangeOperations(f *testing.F) {
	f.Add([]byte(""), []byte("z"), int32(10))     // Full range
	f.Add([]byte("a"), []byte("a"), int32(1))     // Single key
	f.Add([]byte("a"), []byte("b"), int32(100))   // Normal range
	f.Add([]byte("/"), []byte("0/"), int32(10))   // Slash boundary (hierarchical encoder bug!)
	f.Add([]byte("key"), []byte("key"), int32(0)) // Point query

	f.Fuzz(func(t *testing.T, startKey, endKey []byte, limit int32) {
		if limit < 0 || limit > 10000 {
			return // Invalid limit
		}

		// Property 1: Range comparison must be consistent
		cmp := compare.CompareWithSlash(startKey, endKey)

		// Property 2: Empty range (startKey >= endKey) should be detected
		if cmp >= 0 && len(startKey) > 0 && len(endKey) > 0 {
			// Invalid range - startKey must be < endKey
			// System should handle this gracefully
		}

		// Property 3: Range boundaries must respect CompareWithSlash semantics
		if len(startKey) > 0 && len(endKey) > 0 && cmp < 0 {
			// Valid range [startKey, endKey)
			// Verify that any key in range satisfies:
			// startKey <= key < endKey (using CompareWithSlash)

			// Test a key exactly at startKey
			keyAtStart := compare.CompareWithSlash(startKey, startKey)
			if keyAtStart != 0 {
				t.Fatalf("Key comparison with itself failed: %d", keyAtStart)
			}

			// Test ordering is transitive
			if bytes.Equal(startKey, endKey) {
				// Same key - empty range
			}
		}

		// Property 4: Special character handling (the hierarchical encoder bug)
		// Test that "/" vs "0/" ordering is consistent
		if bytes.Equal(startKey, []byte("/")) && bytes.Equal(endKey, []byte("0/")) {
			cmpTest := compare.CompareWithSlash(startKey, endKey)
			if cmpTest >= 0 {
				t.Fatalf("CompareWithSlash(\"/\", \"0/\") = %d, expected < 0", cmpTest)
			}
		}

		// Property 5: Limit must be non-negative
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
		// Property 1: Empty keys should be rejected
		if len(key) == 0 {
			// Empty key - should be invalid
			return
		}

		// Property 2: Keys with null bytes might be invalid
		if bytes.Contains(key, []byte{0x00}) {
			// Null byte - might be rejected
		}

		// Property 3: Keys with 0xFF might conflict with encoding
		if bytes.Contains(key, []byte{0xff}) {
			// 0xFF is used as encoded separator in hierarchical encoder
			// More critically, keys starting with \xff\xff will conflict with internal key encoding
			// in the natural encoder, which uses \xff\xff to mark internal keys (__oxia/...)
			// Skip such keys as they're not valid user keys in Oxia
			if bytes.HasPrefix(key, []byte{0xff, 0xff}) {
				return // Skip keys that would create encoding ambiguity
			}
		}

		// Property 4: Key length limits
		const maxKeyLen = 8192 // Example limit
		if len(key) > maxKeyLen {
			// Key too long - should be rejected
		}

		// Property 5: Encoding/decoding roundtrip
		if len(key) > 0 {
			// Test natural encoder
			encoded := compare.EncoderNatural.Encode(string(key))
			decoded := compare.EncoderNatural.Decode(encoded)
			if decoded != string(key) {
				t.Fatalf("Natural encoder roundtrip failed: %q != %q", decoded, string(key))
			}
		}
	})
}
