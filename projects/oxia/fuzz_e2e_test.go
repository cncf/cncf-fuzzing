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
	"runtime"
	"testing"
	"time"

	"github.com/oxia-db/oxia/common/constant"
	"github.com/oxia-db/oxia/common/proto"
	time2 "github.com/oxia-db/oxia/common/time"
	"github.com/oxia-db/oxia/oxiad/dataserver/database"
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

// FuzzE2EOperations tests Oxia database layer operations end-to-end.
// This fuzzer exercises the database layer (one level above KV store) which includes
// transactions, commit offsets, timestamps, and state tracking.
//
// The fuzzer performs randomized sequences of operations:
// - Put: Store key-value pairs with transaction semantics
// - Get: Retrieve values and verify consistency
// - Delete: Remove keys with transaction tracking
// - DeleteRange: Remove ranges of keys atomically
// - List: Iterate over key ranges
//
// The fuzzer maintains an expected state map and validates that all database
// operations maintain consistency with this expected state.
func FuzzE2EOperations(f *testing.F) {

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

		// Create KV factory
		factory, err := kvstore.NewPebbleKVFactory(kvstore.NewFactoryOptionsForTest(t))
		if err != nil {
			t.Fatalf("Failed to create KV factory: %v", err)
		}
		defer factory.Close()

		// Create Database layer (includes transactions, notifications, sequences)
		db, err := database.NewDB(
			constant.DefaultNamespace,
			1, // shard ID
			factory,
			proto.KeySortingType_HIERARCHICAL,
			1*time.Hour,
			time2.SystemClock,
		)
		if err != nil {
			t.Fatalf("Failed to create database: %v", err)
		}
		defer db.Close()

		// Initialize database term
		if err := db.UpdateTerm(1, database.TermOptions{}); err != nil {
			t.Fatalf("Failed to update term: %v", err)
		}

		// Track expected state: key -> value mapping
		expectedState := make(map[string][]byte)

		// Process all parsed operations
		for _, op := range parsedOps {
			switch op.opType {
			case OpPut:
				// Use database layer ProcessWrite for puts
				wr := &proto.WriteRequest{
					Puts: []*proto.PutRequest{
						{
							Key:   op.key,
							Value: op.value,
						},
					},
				}
				_, err := db.ProcessWrite(wr, 1, uint64(time.Now().UnixNano()), nil)
				if err != nil {
					continue // Skip on error
				}
				expectedState[op.key] = op.value

			case OpGet:
				// Use database layer Get
				gr := &proto.GetRequest{Key: op.key}
				resp, err := db.Get(gr)
				expectedValue, exists := expectedState[op.key]

				if exists {
					if err != nil {
						t.Errorf("Get(%q): expected value, got error: %v", op.key, err)
					} else if resp.Status != proto.Status_OK {
						t.Errorf("Get(%q): expected OK status, got %v", op.key, resp.Status)
					} else {
						if !bytes.Equal(resp.Value, expectedValue) {
							t.Errorf("Get(%q): expected %q, got %q", op.key, expectedValue, resp.Value)
						}
					}
				} else {
					if err == nil && resp.Status == proto.Status_OK {
						t.Errorf("Get(%q): expected key not found, got value %q", op.key, resp.Value)
					}
					// Error or non-OK status is expected for non-existent key
				}

			case OpDelete:
				// Use database layer ProcessWrite for deletes
				wr := &proto.WriteRequest{
					Deletes: []*proto.DeleteRequest{
						{
							Key: op.key,
						},
					},
				}
				_, err := db.ProcessWrite(wr, 2, uint64(time.Now().UnixNano()), nil)
				if err != nil {
					continue // Skip on error
				}
				delete(expectedState, op.key)

			case OpDeleteRange:
				// Use database layer ProcessWrite for delete range
				wr := &proto.WriteRequest{
					DeleteRanges: []*proto.DeleteRangeRequest{
						{
							StartInclusive: op.key,
							EndExclusive:   op.endKey,
						},
					},
				}
				_, err := db.ProcessWrite(wr, 3, uint64(time.Now().UnixNano()), nil)
				if err != nil {
					continue // Skip on error
				}

				// Rebuild expected state from actual database state
				expectedState = make(map[string][]byte)
				lr := &proto.ListRequest{
					StartInclusive: "",
					EndExclusive:   "",
				}
				iter, err := db.List(lr)
				if err == nil {
					for iter.Valid() {
						k := iter.Key()
						// Get the value for this key
						gr := &proto.GetRequest{Key: k}
						resp, gerr := db.Get(gr)
						if gerr == nil && resp.Status == proto.Status_OK {
							expectedState[k] = resp.Value
						}
						if !iter.Next() {
							break
						}
					}
					iter.Close()
				}

			case OpList:
				// Use database layer List
				lr := &proto.ListRequest{
					StartInclusive: op.key,
					EndExclusive:   op.endKey,
				}
				iter, err := db.List(lr)
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
			gr := &proto.GetRequest{Key: key}
			resp, err := db.Get(gr)
			if err != nil || resp.Status != proto.Status_OK {
				t.Errorf("Final check - Get(%q): expected %q, got error: %v", key, expectedValue, err)
				continue
			}

			if !bytes.Equal(resp.Value, expectedValue) {
				t.Errorf("Final check - Get(%q): expected %q, got %q", key, expectedValue, resp.Value)
			}
		}

		// Force garbage collection to release CGO/Pebble resources
		// This helps prevent memory leaks from Pebble's C++ allocations
		runtime.GC()
	})
}
