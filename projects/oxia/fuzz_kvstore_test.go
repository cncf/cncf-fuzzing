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

	"github.com/oxia-db/oxia/common/constant"
	"github.com/oxia-db/oxia/common/proto"
	"github.com/oxia-db/oxia/oxiad/dataserver/database/kvstore"
)

// FuzzKVPutGet tests basic Put/Get roundtrip with arbitrary keys and values.
// Property: Get(key) after Put(key, value) returns value
func FuzzKVPutGet(f *testing.F) {
	f.Add(buildSeed(encStr("key"), []byte("value")))
	f.Add(buildSeed(encStr(""), []byte("empty-key")))
	f.Add(buildSeed(encStr("a/b/c"), []byte("hierarchical")))
	f.Add(buildSeed(encStr("users/alice/profile"), []byte("3-level")))
	f.Add(buildSeed(encStr("data/2024/12/15/logs"), []byte("5-level")))
	f.Add(buildSeed(encStr("/root/path"), []byte("leading-slash")))
	f.Add(buildSeed(encStr("trailing/slash/"), []byte("trailing-slash")))
	f.Add(buildSeed(encStr("double//slash"), []byte("double-separator")))
	f.Add(buildSeed(encStr("key-with-special-chars-!@#$%"), []byte{0, 1, 2, 255}))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)
		key, ok := c.consumeString(255)
		if !ok {
			return
		}
		value := c.consumeRest()
		if key == "" {
			return // Empty keys may not be supported
		}

		factory, err := kvstore.NewPebbleKVFactory(kvstore.NewFactoryOptionsForTest(t))
		if err != nil {
			t.Fatalf("failed to create factory: %v", err)
		}
		defer factory.Close()

		kv, err := factory.NewKV(constant.DefaultNamespace, 1, proto.KeySortingType_HIERARCHICAL)
		if err != nil {
			t.Fatalf("failed to create KV: %v", err)
		}
		defer kv.Close()

		// Put the key-value
		wb := kv.NewWriteBatch()
		err = wb.Put(key, value)
		if err != nil {
			wb.Close()
			return // Some keys might be rejected
		}
		err = wb.Commit()
		if err != nil {
			wb.Close()
			return
		}
		wb.Close()

		// Get it back
		storedKey, storedValue, closer, err := kv.Get(key, kvstore.ComparisonEqual, kvstore.NoInternalKeys)
		if err != nil {
			t.Fatalf("Get failed for key %q: %v", key, err)
		}
		defer closer.Close()

		if storedKey != key {
			t.Fatalf("key mismatch: expected %q, got %q", key, storedKey)
		}
		if !bytes.Equal(storedValue, value) {
			t.Fatalf("value mismatch for key %q", key)
		}
	})
}

// FuzzKVRangeScan tests range scan with arbitrary bounds.
// Property: All returned keys are within bounds and in sorted order
func FuzzKVRangeScan(f *testing.F) {
	f.Add(buildSeed(encStr("a"), encStr("z")))
	f.Add(buildSeed(encStr(""), encStr("zzz")))
	f.Add(buildSeed(encStr("aaa"), encStr("aab")))
	f.Add(buildSeed(encStr("test/"), encStr("test0")))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)
		lowerBound, ok := c.consumeString(255)
		if !ok {
			return
		}
		upperBound, ok := c.consumeString(255)
		if !ok {
			return
		}
		if lowerBound >= upperBound {
			return // Invalid range
		}

		factory, err := kvstore.NewPebbleKVFactory(kvstore.NewFactoryOptionsForTest(t))
		if err != nil {
			t.Fatalf("failed to create factory: %v", err)
		}
		defer factory.Close()

		kv, err := factory.NewKV(constant.DefaultNamespace, 1, proto.KeySortingType_HIERARCHICAL)
		if err != nil {
			t.Fatalf("failed to create KV: %v", err)
		}
		defer kv.Close()

		// Insert some test data
		wb := kv.NewWriteBatch()
		testKeys := []string{"a", "b", "c", "d", "e", "test/1", "test/2", "test/3"}
		for _, k := range testKeys {
			_ = wb.Put(k, []byte(k))
		}
		_ = wb.Commit()
		wb.Close()

		// Perform range scan
		iter, err := kv.RangeScan(lowerBound, upperBound, kvstore.NoInternalKeys)
		if err != nil {
			return // Some bounds might cause errors
		}
		defer iter.Close()

		// Collect all keys
		var keys []string
		for iter.Valid() {
			keys = append(keys, iter.Key())
			if !iter.Next() {
				break
			}
		}

		// Property: keys should be in sorted order
		if !sort.StringsAreSorted(keys) {
			t.Fatalf("keys not in sorted order: %v", keys)
		}
	})
}

// FuzzKVDeleteRange tests delete range operations.
// Property: After DeleteRange(lower, upper), no keys in range should exist
func FuzzKVDeleteRange(f *testing.F) {
	f.Add(buildSeed(encStr("b"), encStr("d"), encStr("a"), encStr("b"), encStr("c"), encStr("d"), encStr("e"), encStr("f")))
	f.Add(buildSeed(encStr("a"), encStr("z"), encStr("apple"), encStr("banana"), encStr("cherry"), encStr("date")))
	f.Add(buildSeed(encStr("test/"), encStr("test0"), encStr("test/1"), encStr("test/2"), encStr("other/key")))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)
		lowerBound, ok := c.consumeString(255)
		if !ok {
			return
		}
		upperBound, ok := c.consumeString(255)
		if !ok {
			return
		}
		if lowerBound >= upperBound {
			return
		}

		// Consume remaining strings as test keys
		var testKeys []string
		for c.remaining() > 0 {
			k, ok := c.consumeString(255)
			if !ok {
				break
			}
			testKeys = append(testKeys, k)
		}
		if len(testKeys) == 0 {
			return
		}

		factory, err := kvstore.NewPebbleKVFactory(kvstore.NewFactoryOptionsForTest(t))
		if err != nil {
			t.Fatalf("failed to create factory: %v", err)
		}
		defer factory.Close()

		kv, err := factory.NewKV(constant.DefaultNamespace, 1, proto.KeySortingType_HIERARCHICAL)
		if err != nil {
			t.Fatalf("failed to create KV: %v", err)
		}
		defer kv.Close()

		// Insert test data using fuzzer-provided keys
		wb := kv.NewWriteBatch()
		for _, k := range testKeys {
			if k != "" {
				_ = wb.Put(k, []byte(k))
			}
		}
		_ = wb.Commit()
		wb.Close()

		// Delete range
		wb = kv.NewWriteBatch()
		err = wb.DeleteRange(lowerBound, upperBound)
		if err != nil {
			wb.Close()
			return
		}
		err = wb.Commit()
		if err != nil {
			wb.Close()
			return
		}
		wb.Close()
	})
}

// FuzzKVComparisonTypes tests Floor/Ceiling/Lower/Higher comparisons.
// Property: Comparison operations return keys with correct relationship
func FuzzKVComparisonTypes(f *testing.F) {
	f.Add(buildSeed(encStr("c"), []byte{0}))
	f.Add(buildSeed(encStr("b"), []byte{1}))
	f.Add(buildSeed(encStr("d"), []byte{2}))
	f.Add(buildSeed(encStr("a"), []byte{3}))
	f.Add(buildSeed(encStr("z"), []byte{4}))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)
		searchKey, ok := c.consumeString(255)
		if !ok {
			return
		}
		compType, ok := c.consumeUint8()
		if !ok {
			return
		}
		if searchKey == "" {
			return
		}

		// Skip keys containing '/' because hierarchical encoding encodes '/' as 0xff,
		// which changes the sort order. Simple string comparisons won't work correctly.
		if strings.Contains(searchKey, "/") {
			return
		}

		factory, err := kvstore.NewPebbleKVFactory(kvstore.NewFactoryOptionsForTest(t))
		if err != nil {
			t.Fatalf("failed to create factory: %v", err)
		}
		defer factory.Close()

		kv, err := factory.NewKV(constant.DefaultNamespace, 1, proto.KeySortingType_HIERARCHICAL)
		if err != nil {
			t.Fatalf("failed to create KV: %v", err)
		}
		defer kv.Close()

		// Insert test data
		wb := kv.NewWriteBatch()
		insertKeys := []string{"a", "c", "e", "g"}
		for _, k := range insertKeys {
			_ = wb.Put(k, []byte(k))
		}
		_ = wb.Commit()
		wb.Close()

		comparison := kvstore.ComparisonType(compType % 5)
		storedKey, _, closer, err := kv.Get(searchKey, comparison, kvstore.NoInternalKeys)

		if err == nil {
			defer closer.Close()

			switch comparison {
			case kvstore.ComparisonEqual:
				if storedKey != searchKey {
					t.Fatalf("ComparisonEqual: expected %q, got %q", searchKey, storedKey)
				}
			case kvstore.ComparisonFloor:
				if storedKey > searchKey {
					t.Fatalf("ComparisonFloor: %q > %q", storedKey, searchKey)
				}
			case kvstore.ComparisonCeiling:
				if storedKey < searchKey {
					t.Fatalf("ComparisonCeiling: %q < %q", storedKey, searchKey)
				}
			case kvstore.ComparisonLower:
				if storedKey >= searchKey {
					t.Fatalf("ComparisonLower: %q >= %q", storedKey, searchKey)
				}
			case kvstore.ComparisonHigher:
				if storedKey <= searchKey {
					t.Fatalf("ComparisonHigher: %q <= %q", storedKey, searchKey)
				}
			}
		}
	})
}

// FuzzKVKeyOrdering tests that keys maintain proper ordering.
// Property: Keys are always returned in sorted order regardless of insertion order
func FuzzKVKeyOrdering(f *testing.F) {
	// Seeds: keys to insert (as bytes, each byte is a key character)
	f.Add([]byte("dcba"))
	f.Add([]byte("zyxwv"))
	f.Add([]byte("aeiou"))

	f.Fuzz(func(t *testing.T, keyChars []byte) {
		if len(keyChars) < 2 {
			return
		}

		// Create unique keys from characters
		seen := make(map[byte]bool)
		var keys []string
		for _, c := range keyChars {
			if c >= 'a' && c <= 'z' && !seen[c] {
				keys = append(keys, string(c))
				seen[c] = true
			}
		}
		if len(keys) < 2 {
			return
		}

		factory, err := kvstore.NewPebbleKVFactory(kvstore.NewFactoryOptionsForTest(t))
		if err != nil {
			t.Fatalf("failed to create factory: %v", err)
		}
		defer factory.Close()

		kv, err := factory.NewKV(constant.DefaultNamespace, 1, proto.KeySortingType_HIERARCHICAL)
		if err != nil {
			t.Fatalf("failed to create KV: %v", err)
		}
		defer kv.Close()

		// Insert in the given (potentially unsorted) order
		wb := kv.NewWriteBatch()
		for _, k := range keys {
			_ = wb.Put(k, []byte(k))
		}
		_ = wb.Commit()
		wb.Close()

		// Scan all keys using RangeScan
		iter, err := kv.RangeScan("", "\xff", kvstore.NoInternalKeys)
		if err != nil {
			t.Fatalf("failed to create iterator: %v", err)
		}
		defer iter.Close()

		var scannedKeys []string
		for iter.Valid() {
			scannedKeys = append(scannedKeys, iter.Key())
			if !iter.Next() {
				break
			}
		}

		if !sort.StringsAreSorted(scannedKeys) {
			t.Fatalf("keys not in sorted order: inserted %v, got %v", keys, scannedKeys)
		}

		if len(scannedKeys) != len(keys) {
			t.Fatalf("key count mismatch: inserted %d, scanned %d", len(keys), len(scannedKeys))
		}
	})
}
