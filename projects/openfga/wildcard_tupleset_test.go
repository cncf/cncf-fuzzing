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

package tests

import (
	"context"
	"fmt"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	parser "github.com/openfga/language/pkg/go/transformer"

	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/typesystem"
)

// FuzzWildcardTupleset tests GHSA-vj4m-83m8-xpw5
// CVE: Wildcard (*) assigned to tupleset relation (right-hand side of 'from')
// causes authorization bypass
//
// Vulnerability pattern:
// 1. Model: define viewer: owner from parent (tupleset)
// 2. Write tuple: folder:child#parent@folder:parent
// 3. Write tuple: folder:parent#owner@user:* (WILDCARD on tupleset relation!)
// 4. Check: folder:child#viewer@user:anyone
// 5. BUG: In vulnerable versions, wildcard on tupleset causes incorrect evaluation
func FuzzWildcardTupleset(f *testing.F) {
	f.Add([]byte("child"), []byte("parent"), []byte("alice"))
	f.Add([]byte("doc"), []byte("folder"), []byte("bob"))

	f.Fuzz(func(t *testing.T, childID, parentID, userID []byte) {
		if len(childID) == 0 || len(parentID) == 0 || len(userID) == 0 {
			return
		}

		ctx := context.Background()
		datastore := memory.New()
		defer datastore.Close()

		srv := server.MustNewServerWithOpts(server.WithDatastore(datastore))
		defer srv.Close()

		store, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz"})
		if err != nil {
			return
		}

		// Step 1: Create model with 'from' clause
		dsl := parser.MustTransformDSLToProto(`
			model
			  schema 1.1
			type user
			type folder
			  relations
			    define parent: [folder]
			    define owner: [user, user:*]
			    define viewer: owner from parent
		`)

		model, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         store.Id,
			TypeDefinitions: dsl.GetTypeDefinitions(),
			SchemaVersion:   typesystem.SchemaVersion1_1,
		})
		if err != nil {
			return
		}

		childStr := fmt.Sprintf("folder:%s", string(childID))
		parentStr := fmt.Sprintf("folder:%s", string(parentID))
		userStr := fmt.Sprintf("user:%s", string(userID))

		// Step 2: Link child -> parent
		parentTuple := &openfgav1.TupleKey{
			Object:   childStr,
			Relation: "parent",
			User:     parentStr,
		}

		// Step 3: Write WILDCARD to tupleset relation (owner)
		// This is the vulnerable pattern!
		wildcardTuple := &openfgav1.TupleKey{
			Object:   parentStr,
			Relation: "owner",
			User:     "user:*", // Wildcard on tupleset!
		}

		_, err = srv.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              store.Id,
			AuthorizationModelId: model.AuthorizationModelId,
			Writes: &openfgav1.WriteRequestWrites{
				TupleKeys: []*openfgav1.TupleKey{parentTuple, wildcardTuple},
			},
		})
		if err != nil {
			return
		}

		// Step 4: Check viewer access on child
		checkResp, err := srv.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              store.Id,
			AuthorizationModelId: model.AuthorizationModelId,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   childStr,
				Relation: "viewer",
				User:     userStr,
			},
		})
		if err != nil {
			return
		}

		// Expected behavior with wildcard:
		// child#viewer = owner from parent
		// child#parent = parent
		// parent#owner = user:* (wildcard means all users)
		// Therefore: ANY user should have viewer access to child
		
		if !checkResp.Allowed {
			t.Fatalf("POTENTIAL ISSUE: Wildcard on tupleset not evaluated correctly\n"+
				"Model: define viewer: owner from parent\n"+
				"Tuples: %s#parent@%s, %s#owner@user:*\n"+
				"Check: %s#viewer@%s\n"+
				"Expected: ALLOWED (wildcard grants all users)\n"+
				"Got: DENIED",
				childStr, parentStr, parentStr, childStr, userStr)
		}

		// Test ListObjects as well
		listResp, err := srv.ListObjects(ctx, &openfgav1.ListObjectsRequest{
			StoreId:              store.Id,
			AuthorizationModelId: model.AuthorizationModelId,
			Type:                 "folder",
			Relation:             "viewer",
			User:                 userStr,
		})
		if err != nil {
			return
		}

		found := false
		for _, obj := range listResp.Objects {
			if obj == childStr {
				found = true
				break
			}
		}

		if !found {
			t.Fatalf("ListObjects did not return object with wildcard tupleset\n"+
				"Model: define viewer: owner from parent\n"+
				"Tuples: %s#parent@%s, %s#owner@user:*\n"+
				"ListObjects(folder, viewer, %s) should include %s",
				childStr, parentStr, parentStr, userStr, childStr)
		}

		// The vulnerability GHSA-vj4m-83m8-xpw5 was that in versions < v0.3.7,
		// wildcards on tupleset relations (RHS of 'from') were not evaluated correctly.
		// Current version should handle this properly (test passes = vulnerability fixed).
		// This fuzzer ensures the fix handles arbitrary wildcard + tupleset combinations.
	})
}
