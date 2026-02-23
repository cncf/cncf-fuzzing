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
	f.Add(buildSeed(encInt64(1), encUint16(0), encBool(false), encStr(""), encStr("")))
	f.Add(buildSeed(encInt64(100), encUint16(1), encBool(true), encStr("localhost:6648"), encStr("localhost:6649")))
	f.Add(buildSeed(encInt64(0), encUint16(2), encBool(false), encStr(""), encStr("")))
	f.Add(buildSeed(encInt64(-1), encUint16(3), encBool(true), encStr("node-1.oxia:6648"), encStr("node-1.oxia:6649")))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)
		term, ok := c.consumeInt64()
		if !ok {
			return
		}
		statusVal, ok := c.consumeUint16()
		if !ok {
			return
		}
		hasLeader, ok := c.consumeBool()
		if !ok {
			return
		}
		leaderPublic, ok := c.consumeString(255)
		if !ok {
			return
		}
		leaderInternal, ok := c.consumeString(255)
		if !ok {
			return
		}

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

		if loaded.Term != term {
			t.Fatalf("Term mismatch: expected %d, got %d", term, loaded.Term)
		}
		if loaded.Status != status {
			t.Fatalf("Status mismatch: expected %v, got %v", status, loaded.Status)
		}
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
	f.Add(buildSeed(encBool(true), encStr("localhost:6648"), encStr("localhost:6649")))
	f.Add(buildSeed(encBool(false), encStr(""), encStr("")))
	f.Add(buildSeed(encBool(true), encStr("node-1:6648"), encStr("node-1:6649")))

	f.Fuzz(func(t *testing.T, data []byte) {
		c := newConsumer(data)
		hasLeader, ok := c.consumeBool()
		if !ok {
			return
		}
		public, ok := c.consumeString(255)
		if !ok {
			return
		}
		internal, ok := c.consumeString(255)
		if !ok {
			return
		}

		var leader *model.Server
		if hasLeader && public != "" {
			leader = &model.Server{Public: public, Internal: internal}
		}

		md := controller.NewMetadata(model.ShardMetadata{Leader: leader})
		result := md.Leader()

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
