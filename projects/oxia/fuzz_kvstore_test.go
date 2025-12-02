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
	// Seeds
	f.Add("key", []byte("value"))
	f.Add("", []byte("empty-key"))
	f.Add("a/b/c", []byte("hierarchical"))
	f.Add("key-with-special-chars-!@#$%", []byte{0, 1, 2, 255})
	f.Add(string(bytes.Repeat([]byte("k"), 1000)), bytes.Repeat([]byte("v"), 10000))

	f.Fuzz(func(t *testing.T, key string, value []byte) {
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

		// Property: stored key should match
		if storedKey != key {
			t.Fatalf("key mismatch: expected %q, got %q", key, storedKey)
		}

		// Property: stored value should match
		if !bytes.Equal(storedValue, value) {
			t.Fatalf("value mismatch for key %q", key)
		}
	})
}

// FuzzKVRangeScan tests range scan with arbitrary bounds.
// Property: All returned keys are within bounds and in sorted order
func FuzzKVRangeScan(f *testing.F) {
	// Seeds: lower bound, upper bound
	f.Add("a", "z")
	f.Add("", "zzz")
	f.Add("aaa", "aab")
	f.Add("test/", "test0") // Hierarchical boundary

	f.Fuzz(func(t *testing.T, lowerBound, upperBound string) {
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

		// Property: all keys should be >= lowerBound and < upperBound
		for _, k := range keys {
			if k < lowerBound || k >= upperBound {
				t.Fatalf("key %q outside bounds [%q, %q)", k, lowerBound, upperBound)
			}
		}
	})
}

// FuzzKVDeleteRange tests delete range operations.
// Property: After DeleteRange(lower, upper), no keys in range should exist
func FuzzKVDeleteRange(f *testing.F) {
	// Seeds
	f.Add("b", "d")
	f.Add("a", "z")
	f.Add("test/", "test0")

	f.Fuzz(func(t *testing.T, lowerBound, upperBound string) {
		if lowerBound >= upperBound {
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
		testKeys := []string{"a", "b", "c", "d", "e", "f"}
		for _, k := range testKeys {
			_ = wb.Put(k, []byte(k))
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

		// Verify no keys in range exist
		for _, k := range testKeys {
			if k >= lowerBound && k < upperBound {
				// This key should be deleted
				_, _, closer, err := kv.Get(k, kvstore.ComparisonEqual, kvstore.NoInternalKeys)
				if err == nil {
					closer.Close()
					t.Fatalf("key %q should have been deleted (in range [%q, %q))", k, lowerBound, upperBound)
				}
			}
		}
	})
}

// FuzzKVWriteBatchAtomicity tests that write batches are atomic.
// Property: Either all operations in a batch succeed or none do

// FuzzKVkvstore.ComparisonTypes tests Floor/Ceiling/Lower/Higher comparisons.
// Property: Comparison operations return keys with correct relationship
func FuzzKVComparisonTypes(f *testing.F) {
	// Seeds: search key, comparison type
	f.Add("c", uint8(0))
	f.Add("b", uint8(1))
	f.Add("d", uint8(2))
	f.Add("a", uint8(3))
	f.Add("z", uint8(4))

	f.Fuzz(func(t *testing.T, searchKey string, compType uint8) {
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
		testKeys := []string{"a", "c", "e", "g"}
		for _, k := range testKeys {
			_ = wb.Put(k, []byte(k))
		}
		_ = wb.Commit()
		wb.Close()

		comparison := kvstore.ComparisonType(compType % 5)
		storedKey, _, closer, err := kv.Get(searchKey, comparison, kvstore.NoInternalKeys)

		if err == nil {
			defer closer.Close()

			// Verify the comparison relationship
			switch comparison {
			case kvstore.ComparisonEqual:
				if storedKey != searchKey {
					t.Fatalf("kvstore.ComparisonEqual: expected %q, got %q", searchKey, storedKey)
				}
			case kvstore.ComparisonFloor:
				// Floor: largest key <= searchKey
				if storedKey > searchKey {
					t.Fatalf("kvstore.ComparisonFloor: %q > %q", storedKey, searchKey)
				}
			case kvstore.ComparisonCeiling:
				// Ceiling: smallest key >= searchKey
				if storedKey < searchKey {
					t.Fatalf("kvstore.ComparisonCeiling: %q < %q", storedKey, searchKey)
				}
			case kvstore.ComparisonLower:
				// Lower: largest key < searchKey
				if storedKey >= searchKey {
					t.Fatalf("kvstore.ComparisonLower: %q >= %q", storedKey, searchKey)
				}
			case kvstore.ComparisonHigher:
				// Higher: smallest key > searchKey
				if storedKey <= searchKey {
					t.Fatalf("kvstore.ComparisonHigher: %q <= %q", storedKey, searchKey)
				}
			}
		}
		// Error is acceptable if no matching key exists
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

		// Scan all keys using RangeScan (KeyIterator requires manual positioning)
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

		// Property: scanned keys must be in sorted order
		if !sort.StringsAreSorted(scannedKeys) {
			t.Fatalf("keys not in sorted order: inserted %v, got %v", keys, scannedKeys)
		}

		// Property: all inserted keys should be present
		if len(scannedKeys) != len(keys) {
			t.Fatalf("key count mismatch: inserted %d, scanned %d", len(keys), len(scannedKeys))
		}
	})
}
