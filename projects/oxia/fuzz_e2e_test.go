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
	"context"
	"errors"
	"testing"

	"github.com/oxia-db/oxia/oxia"
	"github.com/oxia-db/oxia/oxiad/dataserver"
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

// FuzzE2EOperations is an end-to-end style fuzzer that tests the Oxia server
// operations using the public client API. It maintains expected state
// and verifies that operations produce correct results.
//
// The fuzzer takes 20 strings and 5 uint8 operation selectors as input.
// It loops through the 5 operations and uses strings from the pool for keys/values.
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
		// Build string pool
		stringPool := []string{s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19}
		ops := []uint8{op0, op1, op2, op3, op4}

		// Create a fresh server for each test to guarantee clean state
		// This is slower but avoids complex cleanup logic with hierarchical encoding
		dir := t.TempDir()
		server, err := dataserver.NewStandalone(dataserver.NewTestConfig(dir))
		if err != nil {
			t.Fatalf("Failed to create standalone server: %v", err)
		}
		defer server.Close()

		// Create a client to connect to the server
		client, err := oxia.NewSyncClient(server.ServiceAddr())
		if err != nil {
			t.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		ctx := context.Background()

		// Track expected state: key -> value mapping
		expectedState := make(map[string][]byte)

		// String pool index for cycling through strings
		strIdx := 0
		nextString := func() string {
			s := stringPool[strIdx%len(stringPool)]
			strIdx++
			return s
		}

		// Process the 5 operations - each op only consumes strings it needs
		for _, opByte := range ops {
			op := int(opByte) % OpNumOps

			switch op {
			case OpPut:
				key := nextString()
				value := []byte(nextString())
				if key == "" {
					continue
				}
				_, _, err := client.Put(ctx, key, value)
				if err != nil {
					continue
				}
				expectedState[key] = value

			case OpGet:
				key := nextString()
				if key == "" {
					continue
				}
				_, gotValue, _, err := client.Get(ctx, key)
				expectedValue, exists := expectedState[key]

				if exists {
					if err != nil {
						t.Errorf("Get(%q): expected value %q, got error: %v", key, expectedValue, err)
					} else if !bytes.Equal(gotValue, expectedValue) {
						t.Errorf("Get(%q): expected %q, got %q", key, expectedValue, gotValue)
					}
				} else {
					if err == nil {
						t.Errorf("Get(%q): expected error (key not found), got value %q", key, gotValue)
					} else if !errors.Is(err, oxia.ErrKeyNotFound) {
						// Other errors are acceptable (e.g., invalid key)
					}
				}

			case OpDelete:
				key := nextString()
				if key == "" {
					continue
				}
				err := client.Delete(ctx, key)
				if err == nil || errors.Is(err, oxia.ErrKeyNotFound) {
					delete(expectedState, key)
				}

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
				// First, list keys that will be deleted (server uses hierarchical encoding
				// which has different sort order than UTF-8 byte order)
				keysToDelete, _ := client.List(ctx, startKey, endKey)
				err := client.DeleteRange(ctx, startKey, endKey)
				if err == nil {
					// Update expected state based on what the server actually deleted
					for _, k := range keysToDelete {
						delete(expectedState, k)
					}
				}

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
				// Just exercise the List operation - verification is complex due to
				// hierarchical encoding having different sort order than UTF-8 bytes.
				// We verify state correctness via Get operations instead.
				_, _ = client.List(ctx, startKey, endKey)
			}
		}

		// Final verification: all expected keys should exist with correct values
		for key, expectedValue := range expectedState {
			_, gotValue, _, err := client.Get(ctx, key)
			if err != nil {
				t.Errorf("Final check - Get(%q): expected %q, got error: %v", key, expectedValue, err)
			} else if !bytes.Equal(gotValue, expectedValue) {
				t.Errorf("Final check - Get(%q): expected %q, got %q", key, expectedValue, gotValue)
			}
		}
	})
}
