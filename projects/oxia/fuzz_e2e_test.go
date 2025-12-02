// Copyright 2023-2025 The Oxia Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fuzz

import (
	"bytes"
	"testing"

	"github.com/oxia-db/oxia/common/constant"
	"github.com/oxia-db/oxia/common/proto"
	"github.com/oxia-db/oxia/oxiad/dataserver/database/kvstore"
)

// Operation types for the fuzzer - each byte determines which operation to execute
const (
	OpPut         = iota // Put a key-value pair
	OpGet                // Get a key
	OpDelete             // Delete a key
	OpDeleteRange        // Delete a range of keys
	OpList               // List keys in a range
	OpNumOps             // Total number of operations (for modulo)
)

// fuzzOp represents a parsed operation to be executed
type fuzzOp struct {
	opType int
	key    string
	value  []byte
	endKey string // For range operations
}

// parseOperations parses the input into operations BEFORE setting up heavy infrastructure.
// This allows the fuzzer to skip inputs that don't have enough valid operations.
func parseOperations(stringPool []string, ops []uint8) []fuzzOp {
	var result []fuzzOp
	strIdx := 0

	nextString := func() string {
		s := stringPool[strIdx%len(stringPool)]
		strIdx++
		return s
	}

	for _, opByte := range ops {
		op := int(opByte) % OpNumOps

		switch op {
		case OpPut:
			key := nextString()
			value := []byte(nextString())
			if key == "" {
				continue
			}
			result = append(result, fuzzOp{opType: OpPut, key: key, value: value})

		case OpGet:
			key := nextString()
			if key == "" {
				continue
			}
			result = append(result, fuzzOp{opType: OpGet, key: key})

		case OpDelete:
			key := nextString()
			if key == "" {
				continue
			}
			result = append(result, fuzzOp{opType: OpDelete, key: key})

		case OpDeleteRange:
			startKey := nextString()
			endKey := nextString()
			// Ensure startKey < endKey for valid ranges
			if startKey > endKey {
				startKey, endKey = endKey, startKey
			}
			if startKey == endKey {
				endKey = endKey + "\xff"
			}
			if startKey == "" || endKey == "" {
				continue
			}
			result = append(result, fuzzOp{opType: OpDeleteRange, key: startKey, endKey: endKey})

		case OpList:
			startKey := nextString()
			endKey := nextString()
			// Ensure startKey < endKey for valid ranges
			if startKey > endKey {
				startKey, endKey = endKey, startKey
			}
			if startKey == endKey {
				endKey = endKey + "\xff"
			}
			result = append(result, fuzzOp{opType: OpList, key: startKey, endKey: endKey})
		}
	}

	return result
}

// FuzzE2EOperations is an end-to-end style fuzzer that tests Oxia KV store
// operations directly against the kvstore layer. It maintains expected state
// and verifies that operations produce correct results.
//
// This fuzzer is optimized for speed by:
// 1. Parsing and validating operations BEFORE creating any infrastructure
// 2. Using kvstore.KV directly (the lowest level) - no DB layer, no WAL, no RPC
// 3. Skipping inputs that don't have at least 2 valid operations
//
// The fuzzer takes 20 strings and 5 uint8 operation selectors as input.
func FuzzE2EOperations(f *testing.F) {
	// Seeds with different operation sequences
	f.Add(
		"key1", "key2", "key3", "val1", "val2", "val3", "foo", "bar", "baz", "test",
		"a", "b", "c", "d", "e", "x", "y", "z", "alpha", "beta",
		uint8(0), uint8(1), uint8(2), uint8(3), uint8(4),
	)
	f.Add(
		"apple", "banana", "cherry", "date", "elder", "fig", "grape", "honey", "ice", "jam",
		"kiwi", "lemon", "mango", "nut", "orange", "pear", "quince", "rasp", "straw", "tomato",
		uint8(0), uint8(0), uint8(1), uint8(2), uint8(3),
	)
	f.Add(
		"", "k", "ke", "key", "keys", "value", "data", "item", "node", "entry",
		"record", "field", "row", "col", "cell", "doc", "file", "path", "name", "id",
		uint8(4), uint8(3), uint8(2), uint8(1), uint8(0),
	)

	f.Fuzz(func(t *testing.T,
		s0, s1, s2, s3, s4, s5, s6, s7, s8, s9 string,
		s10, s11, s12, s13, s14, s15, s16, s17, s18, s19 string,
		op0, op1, op2, op3, op4 uint8,
	) {
		// Build string pool and operation list
		stringPool := []string{s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19}
		ops := []uint8{op0, op1, op2, op3, op4}

		// Parse operations BEFORE setting up any infrastructure
		// This allows us to skip invalid inputs quickly
		parsedOps := parseOperations(stringPool, ops)
		if len(parsedOps) < 2 {
			return // Skip if not enough valid operations
		}

		// Create KV store using test options (disk-based but fast)
		factory, err := kvstore.NewPebbleKVFactory(kvstore.NewFactoryOptionsForTest(t))
		if err != nil {
			t.Fatalf("Failed to create KV factory: %v", err)
		}
		defer factory.Close()

		kv, err := factory.NewKV(constant.DefaultNamespace, 1, proto.KeySortingType_HIERARCHICAL)
		if err != nil {
			t.Fatalf("Failed to create KV: %v", err)
		}
		defer kv.Close()

		// Track expected state: key -> value mapping
		expectedState := make(map[string][]byte)

		// Process all parsed operations
		for _, op := range parsedOps {
			switch op.opType {
			case OpPut:
				wb := kv.NewWriteBatch()
				if err := wb.Put(op.key, op.value); err != nil {
					wb.Close()
					continue
				}
				if err := wb.Commit(); err != nil {
					wb.Close()
					continue
				}
				wb.Close()
				expectedState[op.key] = op.value

			case OpGet:
				storedKey, storedValue, closer, err := kv.Get(op.key, kvstore.ComparisonEqual, kvstore.NoInternalKeys)
				expectedValue, exists := expectedState[op.key]

				if exists {
					if err != nil {
						t.Errorf("Get(%q): expected value, got error: %v", op.key, err)
					} else {
						if storedKey != op.key {
							t.Errorf("Get(%q): key mismatch, got %q", op.key, storedKey)
						}
						if !bytes.Equal(storedValue, expectedValue) {
							t.Errorf("Get(%q): expected %q, got %q", op.key, expectedValue, storedValue)
						}
						closer.Close()
					}
				} else {
					if err == nil {
						closer.Close()
						t.Errorf("Get(%q): expected key not found, got value %q", op.key, storedValue)
					}
					// Error is expected for non-existent key
				}

			case OpDelete:
				wb := kv.NewWriteBatch()
				if err := wb.Delete(op.key); err != nil {
					wb.Close()
					continue
				}
				if err := wb.Commit(); err != nil {
					wb.Close()
					continue
				}
				wb.Close()
				delete(expectedState, op.key)

			case OpDeleteRange:
				// First list keys that will be deleted
				var keysToDelete []string
				iter, err := kv.KeyRangeScan(op.key, op.endKey, kvstore.NoInternalKeys)
				if err == nil {
					for iter.Valid() {
						keysToDelete = append(keysToDelete, iter.Key())
						if !iter.Next() {
							break
						}
					}
					iter.Close()
				}

				// Perform delete range
				wb := kv.NewWriteBatch()
				if err := wb.DeleteRange(op.key, op.endKey); err != nil {
					wb.Close()
					continue
				}
				if err := wb.Commit(); err != nil {
					wb.Close()
					continue
				}
				wb.Close()

				for _, k := range keysToDelete {
					delete(expectedState, k)
				}

			case OpList:
				// Just exercise the List operation
				iter, err := kv.KeyRangeScan(op.key, op.endKey, kvstore.NoInternalKeys)
				if err == nil {
					for iter.Valid() {
						_ = iter.Key()
						if !iter.Next() {
							break
						}
					}
					iter.Close()
				}
			}
		}

		// Final verification: all expected keys should exist with correct values
		for key, expectedValue := range expectedState {
			storedKey, storedValue, closer, err := kv.Get(key, kvstore.ComparisonEqual, kvstore.NoInternalKeys)
			if err != nil {
				t.Errorf("Final check - Get(%q): expected %q, got error: %v", key, expectedValue, err)
				continue
			}
			defer closer.Close()

			if storedKey != key {
				t.Errorf("Final check - Get(%q): key mismatch, got %q", key, storedKey)
			}
			if !bytes.Equal(storedValue, expectedValue) {
				t.Errorf("Final check - Get(%q): expected %q, got %q", key, expectedValue, storedValue)
			}
		}
	})
}
