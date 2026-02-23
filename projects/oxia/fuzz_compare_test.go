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
	"sort"
	"strings"
	"testing"

	"github.com/oxia-db/oxia/common/compare"
	"github.com/stretchr/testify/require"
)

// FuzzHierarchicalEncodeDecode tests the roundtrip property of hierarchical encoding.
func FuzzHierarchicalEncodeDecode(f *testing.F) {
	f.Add("")
	f.Add("a")
	f.Add("/")
	f.Add("//")
	f.Add("/a")
	f.Add("/a/b")
	f.Add("/a/b/c")
	f.Add("__oxia/internal")
	f.Add("key-without-slashes")
	f.Add("unicode-世界")
	f.Add(string([]byte{0, 1, 2, 255}))

	f.Fuzz(func(t *testing.T, key string) {
		if strings.Contains(key, "\xff") {
			return
		}

		encoder := compare.EncoderHierarchical

		encoded := encoder.Encode(key)
		decoded := encoder.Decode(encoded)
		require.Equal(t, key, decoded, "Roundtrip must preserve key")

		encoded2 := encoder.Encode(key)
		require.Equal(t, encoded, encoded2, "Encoding must be deterministic")

		require.Equal(t, len(key)+2, len(encoded), "Encoded length should be key length + 2")
	})
}

// FuzzNaturalEncodeDecode tests the roundtrip property of natural encoding.
func FuzzNaturalEncodeDecode(f *testing.F) {
	f.Add("")
	f.Add("normal-key")
	f.Add("__oxia/internal")
	f.Add("__oxia/")
	f.Add("__not-internal")
	f.Add("unicode-测试")

	f.Fuzz(func(t *testing.T, key string) {
		if strings.Contains(key, "\xff") {
			return
		}

		encoder := compare.EncoderNatural

		encoded := encoder.Encode(key)
		encodedCopy := append([]byte{}, encoded...)
		decoded := encoder.Decode(encodedCopy)
		require.Equal(t, key, decoded, "Roundtrip must preserve key")

		encoded2 := encoder.Encode(key)
		require.Equal(t, encoded, encoded2, "Encoding must be deterministic")
	})
}

// FuzzEncodingPreservesOrder tests that encoding preserves key ordering.
func FuzzEncodingPreservesOrder(f *testing.F) {
	f.Add(buildSeed(encStr("a"), encStr("b")))
	f.Add(buildSeed(encStr(""), encStr("a")))
	f.Add(buildSeed(encStr("/a"), encStr("/b")))
	f.Add(buildSeed(encStr("/a"), encStr("/a/b")))
	f.Add(buildSeed(encStr("key1"), encStr("key2")))
	f.Add(buildSeed(encStr("normal"), encStr("__oxia/internal")))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)
		key1, ok := c.consumeString(255)
		if !ok {
			return
		}
		key2, ok := c.consumeString(255)
		if !ok {
			return
		}

		if strings.Contains(key1, "\xff") || strings.Contains(key2, "\xff") {
			return
		}

		// Test Natural encoder
		natEncoded1 := compare.EncoderNatural.Encode(key1)
		natEncoded2 := compare.EncoderNatural.Encode(key2)
		originalCmp := compareStrings(key1, key2)
		natEncodedCmp := bytes.Compare(natEncoded1, natEncoded2)

		isInternal1 := len(key1) >= 7 && key1[:7] == "__oxia/"
		isInternal2 := len(key2) >= 7 && key2[:7] == "__oxia/"

		if isInternal1 == isInternal2 {
			require.Equal(t, sign(originalCmp), sign(natEncodedCmp),
				"Natural encoder: Order must be preserved for same-type keys: cmp(%q, %q)=%d but cmp(encoded)=%d",
				key1, key2, originalCmp, natEncodedCmp)
		} else if !isInternal1 && isInternal2 {
			require.Less(t, natEncodedCmp, 0,
				"Natural encoder: Regular key %q must sort before internal key %q",
				key1, key2)
		} else {
			require.Greater(t, natEncodedCmp, 0,
				"Natural encoder: Internal key %q must sort after regular key %q",
				key1, key2)
		}

		if key1 == key2 {
			require.Equal(t, 0, natEncodedCmp, "Equal keys must encode to equal values")

			hierEncoded1 := compare.EncoderHierarchical.Encode(key1)
			hierEncoded2 := compare.EncoderHierarchical.Encode(key2)
			require.Equal(t, 0, bytes.Compare(hierEncoded1, hierEncoded2), "Equal keys must encode to equal values")
		}
	})
}

// FuzzHierarchicalSortingProperties tests hierarchical sorting invariants.
func FuzzHierarchicalSortingProperties(f *testing.F) {
	f.Add(buildSeed(encStr("parent"), encStr("parent/child")))
	f.Add(buildSeed(encStr("/a"), encStr("/a/b/c")))
	f.Add(buildSeed(encStr("user-key"), encStr("__oxia/internal")))
	f.Add(buildSeed(encStr("/path"), encStr("/path/")))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)
		key1, ok := c.consumeString(255)
		if !ok {
			return
		}
		key2, ok := c.consumeString(255)
		if !ok {
			return
		}

		encoder := compare.EncoderHierarchical
		enc1 := encoder.Encode(key1)
		enc2 := encoder.Encode(key2)
		cmpResult := bytes.Compare(enc1, enc2)

		// Property 1: Parent before child
		if len(key2) > len(key1)+1 && key2[:len(key1)+1] == key1+"/" {
			require.Less(t, cmpResult, 0, "Parent %q must sort before child %q", key1, key2)
		}

		// Property 2: Internal keys sort last
		isInternal1 := len(key1) >= 7 && key1[:7] == "__oxia/"
		isInternal2 := len(key2) >= 7 && key2[:7] == "__oxia/"

		if !isInternal1 && isInternal2 {
			require.Less(t, cmpResult, 0, "Regular key %q must sort before internal key %q", key1, key2)
		}
		if isInternal1 && !isInternal2 {
			require.Greater(t, cmpResult, 0, "Internal key %q must sort after regular key %q", key1, key2)
		}
	})
}

// FuzzCompareWithSlashProperties tests comparison function properties.
func FuzzCompareWithSlashProperties(f *testing.F) {
	f.Add(buildSeed(encStr("a"), encStr("b"), encStr("c")))
	f.Add(buildSeed(encStr("/a"), encStr("/b"), encStr("/c")))
	f.Add(buildSeed(encStr("/a/b"), encStr("/a/c"), encStr("/a/d")))
	f.Add(buildSeed(encStr(""), encStr("a"), encStr("aa")))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)
		key1, ok := c.consumeString(255)
		if !ok {
			return
		}
		key2, ok := c.consumeString(255)
		if !ok {
			return
		}
		key3, ok := c.consumeString(255)
		if !ok {
			return
		}

		k1, k2, k3 := []byte(key1), []byte(key2), []byte(key3)

		// Property 1: Reflexivity
		require.Equal(t, 0, compare.CompareWithSlash(k1, k1), "compare(a, a) must be 0")

		// Property 2: Antisymmetry
		cmp12 := compare.CompareWithSlash(k1, k2)
		cmp21 := compare.CompareWithSlash(k2, k1)
		require.Equal(t, -cmp12, cmp21, "compare(a, b) must equal -compare(b, a)")

		// Property 3: Transitivity
		cmp23 := compare.CompareWithSlash(k2, k3)
		cmp13 := compare.CompareWithSlash(k1, k3)
		if cmp12 < 0 && cmp23 < 0 {
			require.Less(t, cmp13, 0, "Transitivity: if a<b and b<c, then a<c")
		}
		if cmp12 > 0 && cmp23 > 0 {
			require.Greater(t, cmp13, 0, "Transitivity: if a>b and b>c, then a>c")
		}

		// Property 4: For keys without slashes, matches bytes.Compare
		if !bytes.Contains(k1, []byte{'/'}) && !bytes.Contains(k2, []byte{'/'}) {
			standardCmp := bytes.Compare(k1, k2)
			slashCmp := compare.CompareWithSlash(k1, k2)
			require.Equal(t, sign(standardCmp), sign(slashCmp),
				"Without slashes, CompareWithSlash should match bytes.Compare")
		}
	})
}

// FuzzSortingStability tests encoder self-consistency.
func FuzzSortingStability(f *testing.F) {
	f.Add([]byte("a\nb\nc\nd"))

	f.Fuzz(func(t *testing.T, data []byte) {
		keys := bytes.Split(data, []byte{'\n'})
		if len(keys) < 2 || len(keys) > 50 {
			return
		}

		var validKeys []string
		for _, k := range keys {
			if len(k) <= 128 {
				validKeys = append(validKeys, string(k))
			}
		}
		if len(validKeys) < 2 {
			return
		}

		sorted1 := make([]string, len(validKeys))
		copy(sorted1, validKeys)
		sort.Slice(sorted1, func(i, j int) bool {
			enc1 := compare.EncoderHierarchical.Encode(sorted1[i])
			enc2 := compare.EncoderHierarchical.Encode(sorted1[j])
			return bytes.Compare(enc1, enc2) < 0
		})

		sorted2 := make([]string, len(validKeys))
		copy(sorted2, validKeys)
		sort.Slice(sorted2, func(i, j int) bool {
			enc1 := compare.EncoderHierarchical.Encode(sorted2[i])
			enc2 := compare.EncoderHierarchical.Encode(sorted2[j])
			return bytes.Compare(enc1, enc2) < 0
		})

		require.Equal(t, sorted1, sorted2, "Encoded sorting must be deterministic")

		for i := 0; i < len(sorted1)-1; i++ {
			enc1 := compare.EncoderHierarchical.Encode(sorted1[i])
			enc2 := compare.EncoderHierarchical.Encode(sorted1[i+1])
			require.LessOrEqual(t, bytes.Compare(enc1, enc2), 0,
				"Sorted order must be transitive: %q should <= %q", sorted1[i], sorted1[i+1])
		}
	})
}

// Helper functions

func compareStrings(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func sign(n int) int {
	if n < 0 {
		return -1
	}
	if n > 0 {
		return 1
	}
	return 0
}
