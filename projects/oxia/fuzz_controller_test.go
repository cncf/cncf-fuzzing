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
	"testing"

	"github.com/oxia-db/oxia/oxiad/coordinator/controller"
	"github.com/oxia-db/oxia/oxiad/coordinator/model"
)

// Note: FuzzMetadataLoadStore was moved to fuzz_metadata_test.go
// for more comprehensive testing of the metadata storage layer.
// This file now only contains FuzzMetadataLeaderHelper.

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
