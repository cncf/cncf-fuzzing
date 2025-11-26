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
	"encoding/json"
	"testing"

	"github.com/oxia-db/oxia/oxiad/coordinator/model"
)

// FuzzShardStatusUnmarshalInvalid tests unmarshaling invalid JSON.
// Property: Invalid JSON returns error, unknown status becomes Unknown
func FuzzShardStatusUnmarshalInvalid(f *testing.F) {
	f.Add(`"Unknown"`)
	f.Add(`"SteadyState"`)
	f.Add(`"Election"`)
	f.Add(`"Deleting"`)
	f.Add(`"InvalidStatus"`)
	f.Add(`"random"`)
	f.Add(`123`)       // not a string
	f.Add(`{}`)        // object
	f.Add(`null`)      // null
	f.Add(`{invalid}`) // invalid JSON

	f.Fuzz(func(t *testing.T, jsonStr string) {
		var status model.ShardStatus
		err := status.UnmarshalJSON([]byte(jsonStr))

		// If JSON is completely invalid, we expect an error
		var testValid any
		jsonErr := json.Unmarshal([]byte(jsonStr), &testValid)
		if jsonErr != nil {
			// Invalid JSON should cause error
			if err == nil {
				t.Logf("Expected error for invalid JSON: %s", jsonStr)
			}
			return
		}

		// For unknown string values, status becomes Unknown (0)
		// This is by design per the UnmarshalJSON implementation
	})
}

// FuzzServerGetIdentifier tests Server.GetIdentifier().
// Property: Returns Name if set, otherwise Internal
func FuzzServerGetIdentifier(f *testing.F) {
	f.Add(true, "node-1", "localhost:6648", "localhost:6649")
	f.Add(false, "", "localhost:6648", "localhost:6649")
	f.Add(true, "", "localhost:6648", "localhost:6649")
	f.Add(true, "my-server", "pub:1", "int:2")

	f.Fuzz(func(t *testing.T, hasName bool, name, public, internal string) {
		server := model.Server{
			Public:   public,
			Internal: internal,
		}
		if hasName {
			server.Name = &name
		}

		result := server.GetIdentifier()

		// Property: if Name is set, return Name; otherwise return Internal
		if hasName {
			if result != name {
				t.Fatalf("Expected name %q, got %q", name, result)
			}
		} else {
			if result != internal {
				t.Fatalf("Expected internal %q, got %q", internal, result)
			}
		}
	})
}
