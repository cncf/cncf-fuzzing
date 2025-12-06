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

	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/typesystem"
)

// FuzzPublicUsersetConfusion tests GHSA-g4v5-6f5p-m38j
// CVE: When relation allows BOTH public access (user:*) AND userset (user#manager)
// WITH THE SAME TYPE, and only public tuple exists, Check with userset incorrectly returns allowed
//
// Vulnerability pattern:
// 1. Model: define viewer: [user, user:*, user#manager] (public + userset, SAME type "user")
// 2. Write tuple: document:1#viewer@user:* (type-bound public access)
// 3. NO tuple for user#manager
// 4. Check with user=user:alice#manager (userset with same type as public access)
// 5. BUG: Returns allowed (should deny - no userset tuple exists, only public)
func FuzzPublicUsersetConfusion(f *testing.F) {
	f.Add([]byte("doc1"), []byte("alice"))
	f.Add([]byte("file"), []byte("bob"))

	f.Fuzz(func(t *testing.T, objectID, userID []byte) {
		if len(objectID) == 0 || len(userID) == 0 {
			return
		}

		ctx := context.Background()
		datastore := memory.New()
		defer datastore.Close()

		srv := newEnhancedFuzzServer(datastore)
		defer srv.Close()

		store, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz"})
		if err != nil {
			return
		}

		// Step 1: Create model with BOTH public AND userset WITH SAME TYPE
		// Key: user:* (type-bound public) and user#manager (userset) both have type "user"
		dsl := parser.MustTransformDSLToProto(`
			model
			  schema 1.1
			type user
			  relations
			    define manager: [user]
			type document
			  relations
			    define viewer: [user, user:*, user#manager]
		`)

		model, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         store.Id,
			TypeDefinitions: dsl.GetTypeDefinitions(),
			SchemaVersion:   typesystem.SchemaVersion1_1,
		})
		if err != nil {
			return
		}

		objStr := fmt.Sprintf("document:%s", string(objectID))
		userStr := fmt.Sprintf("user:%s", string(userID))

		// Step 2: Write ONLY public access tuple (user:*)
		publicTuple := &openfgav1.TupleKey{
			Object:   objStr,
			Relation: "viewer",
			User:     "user:*",
		}

		_, err = srv.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              store.Id,
			AuthorizationModelId: model.AuthorizationModelId,
			Writes:               &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{publicTuple}},
		})
		if err != nil {
			return
		}

		// Step 3: Explicitly verify NO userset tuple exists
		// (we didn't write user:X#manager as viewer)

		// Step 4 & 5: Check with USERSET as user
		usersetStr := fmt.Sprintf("%s#manager", userStr)
		checkResp, err := srv.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              store.Id,
			AuthorizationModelId: model.AuthorizationModelId,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   objStr,
				Relation: "viewer",
				User:     usersetStr, // Userset, not concrete user
			},
		})
		if err != nil {
			return
		}

		// VULNERABILITY CHECK
		// We only wrote user:* tuple, NOT user:X#manager tuple
		// Check with user:X#manager should return FALSE
		if checkResp.Allowed {
			t.Fatalf("VULNERABILITY GHSA-g4v5-6f5p-m38j DETECTED!\n"+
				"Relation allows [user, user:*, user#manager] (SAME type)\n"+
				"Only tuple written: user:* (type-bound public access)\n"+
				"Check with userset %s incorrectly returned ALLOWED\n"+
				"Should deny because no userset tuple exists",
				usersetStr)
		}

		// Also test ListObjects
		listResp, err := srv.ListObjects(ctx, &openfgav1.ListObjectsRequest{
			StoreId:              store.Id,
			AuthorizationModelId: model.AuthorizationModelId,
			Type:                 "document",
			Relation:             "viewer",
			User:                 usersetStr,
		})
		if err != nil {
			return
		}

		// Should NOT return the object
		for _, obj := range listResp.Objects {
			if obj == objStr {
				t.Fatalf("VULNERABILITY GHSA-g4v5-6f5p-m38j in ListObjects!\n"+
					"ListObjects returned %s for userset %s\n"+
					"But only public tuple (user:*) exists, no userset tuple",
					objStr, usersetStr)
			}
		}
	})
}
