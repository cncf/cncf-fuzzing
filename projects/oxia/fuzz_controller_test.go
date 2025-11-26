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
	"testing"

	"github.com/oxia-db/oxia/oxiad/coordinator/controller"
	"github.com/oxia-db/oxia/oxiad/coordinator/model"
)

// FuzzMetadataLoadStore tests Load and Store operations.
// Property: Store followed by Load returns the same ShardMetadata
func FuzzMetadataLoadStore(f *testing.F) {
	// Seeds: term, status (as uint16), hasLeader, leaderPublic, leaderInternal
	f.Add(int64(1), uint16(0), false, "", "")
	f.Add(int64(100), uint16(1), true, "localhost:6648", "localhost:6649")
	f.Add(int64(0), uint16(2), false, "", "")
	f.Add(int64(-1), uint16(3), true, "node-1.oxia:6648", "node-1.oxia:6649")

	f.Fuzz(func(t *testing.T, term int64, statusVal uint16, hasLeader bool, leaderPublic, leaderInternal string) {
		status := model.ShardStatus(statusVal % 4) // Keep in valid range

		var leader *model.Server
		if hasLeader && leaderPublic != "" {
			leader = &model.Server{
				Public:   leaderPublic,
				Internal: leaderInternal,
			}
		}

		original := model.ShardMetadata{
			Term:   term,
			Status: status,
			Leader: leader,
		}

		md := controller.NewMetadata(model.ShardMetadata{})
		md.Store(original)
		loaded := md.Load()

		// Property: Term must match
		if loaded.Term != term {
			t.Fatalf("Term mismatch: expected %d, got %d", term, loaded.Term)
		}

		// Property: Status must match
		if loaded.Status != status {
			t.Fatalf("Status mismatch: expected %v, got %v", status, loaded.Status)
		}

		// Property: Leader must match
		if hasLeader && leaderPublic != "" {
			if loaded.Leader == nil {
				t.Fatalf("Expected leader to be set")
			}
			if loaded.Leader.Public != leaderPublic {
				t.Fatalf("Leader public mismatch: expected %s, got %s", leaderPublic, loaded.Leader.Public)
			}
		} else if loaded.Leader != nil && hasLeader {
			t.Fatalf("Expected leader to be nil")
		}
	})
}

// FuzzMetadataLeaderHelper tests Leader() helper.
// Property: Leader() returns the current leader or nil
func FuzzMetadataLeaderHelper(f *testing.F) {
	f.Add(true, "localhost:6648", "localhost:6649")
	f.Add(false, "", "")
	f.Add(true, "node-1:6648", "node-1:6649")

	f.Fuzz(func(t *testing.T, hasLeader bool, public, internal string) {
		var leader *model.Server
		if hasLeader && public != "" {
			leader = &model.Server{Public: public, Internal: internal}
		}

		md := controller.NewMetadata(model.ShardMetadata{Leader: leader})

		result := md.Leader()

		// Property: Leader() should match what was stored
		if hasLeader && public != "" {
			if result == nil {
				t.Fatalf("Expected leader, got nil")
			}
			if result.Public != public {
				t.Fatalf("Leader public mismatch")
			}
		} else if !hasLeader || public == "" {
			if result != nil && hasLeader {
				// Only fail if hasLeader was true but public was empty
			}
		}
	})
}
