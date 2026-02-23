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
	"runtime"
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
// operations directly against the kvstore layer. It uses a consumer to extract
// operation selectors and a string pool from a single []byte input.
func FuzzE2EOperations(f *testing.F) {
	f.Add(buildSeed(
		[]byte{0, 1, 0, 3, 4}, // ops: Put, Get, Put, DeleteRange, List
		encStr("users/alice"), encStr("users/bob"), encStr("data/2024"),
		encStr("config/db"), encStr("api/v1"), encStr("cache/session"),
	))
	f.Add(buildSeed(
		[]byte{0, 0, 1, 1, 2}, // ops: Put, Put, Get, Get, Delete
		encStr("key1"), encStr("val1"), encStr("key2"), encStr("val2"),
		encStr("foo/bar"), encStr("foo/baz"),
	))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)

		// Consume 5 operation selector bytes
		var ops []uint8
		for i := 0; i < 5; i++ {
			op, ok := c.consumeUint8()
			if !ok {
				return
			}
			ops = append(ops, op)
		}

		// Consume string pool from remaining data
		var stringPool []string
		for c.remaining() > 0 {
			s, ok := c.consumeString(64)
			if !ok {
				break
			}
			stringPool = append(stringPool, s)
		}
		if len(stringPool) < 2 {
			return
		}

		// Parse operations BEFORE setting up any infrastructure
		parsedOps := parseOperations(stringPool, ops)
		if len(parsedOps) < 2 {
			return
		}

		// Create KV store
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
						if closer != nil {
							closer.Close()
						}
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
					} else if closer != nil {
						closer.Close()
					}
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

				// Rebuild expected state from actual KV state
				expectedState = make(map[string][]byte)
				iter, err := kv.RangeScan("", "\xff\xff\xff\xff", kvstore.NoInternalKeys)
				if err == nil {
					for iter.Valid() {
						k := iter.Key()
						v, err := iter.Value()
						if err == nil {
							expectedState[k] = v
						}
						if !iter.Next() {
							break
						}
					}
					iter.Close()
				}

			case OpList:
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

		// Final verification
		for key, expectedValue := range expectedState {
			storedKey, storedValue, closer, err := kv.Get(key, kvstore.ComparisonEqual, kvstore.NoInternalKeys)
			if err != nil {
				t.Errorf("Final check - Get(%q): expected %q, got error: %v", key, expectedValue, err)
				continue
			}
			if storedKey != key {
				t.Errorf("Final check - Get(%q): key mismatch, got %q", key, storedKey)
			}
			if !bytes.Equal(storedValue, expectedValue) {
				t.Errorf("Final check - Get(%q): expected %q, got %q", key, expectedValue, storedValue)
			}
			closer.Close()
		}

		runtime.GC()
	})
}
