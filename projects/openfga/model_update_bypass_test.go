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
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"

	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/typesystem"
)

// FuzzModelUpdateBypass tests GHSA-m3q4-7qmj-657m
// CVE: When model is updated with different type restrictions, old tuples
// incorrectly continue to grant access despite type mismatch
//
// Vulnerability pattern:
// 1. Create model v1: define viewer: [user]
// 2. Write tuple: document:1#viewer@user:alice
// 3. Update to model v2: define viewer: [employee] (different type!)
// 4. Check with old tuple against new model
// 5. BUG: Should deny (type mismatch) but allows access
func FuzzModelUpdateBypass(f *testing.F) {
	f.Add([]byte("doc1"), []byte("alice"), []byte("user"), []byte("employee"))
	f.Add([]byte("file"), []byte("bob"), []byte("member"), []byte("admin"))

	f.Fuzz(func(t *testing.T, objectID, userID, type1, type2 []byte) {
		if len(objectID) == 0 || len(userID) == 0 || len(type1) == 0 || len(type2) == 0 {
			return
		}

		// Skip if types are the same (not a vulnerability scenario)
		if string(type1) == string(type2) {
			return
		}

		ctx := context.Background()
		datastore := memory.New()
		defer datastore.Close()

		srv := newEnhancedFuzzServer(datastore)
		defer srv.Close()

		store, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz"})
		require.NoError(t, err)

		// Step 1: Create model v1 with type1 restriction
		type1Str := string(type1)
		dslV1 := fmt.Sprintf(`
			model
			  schema 1.1
			type user
			type %s
			type document
			  relations
			    define viewer: [%s]
		`, type1Str, type1Str)

		modelV1DSL, err := transformDSLWithTimeout(dslV1, 5*time.Second)
		if err != nil {
			return // Invalid DSL or timeout, skip
		}

		modelV1, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         store.Id,
			TypeDefinitions: modelV1DSL.GetTypeDefinitions(),
			SchemaVersion:   typesystem.SchemaVersion1_1,
		})
		if err != nil {
			return // Invalid model, skip
		}

		// Step 2: Write tuple using model v1's type
		userStr := fmt.Sprintf("%s:%s", type1Str, string(userID))
		docObj := fmt.Sprintf("document:%s", string(objectID))

		tuple := &openfgav1.TupleKey{
			Object:   docObj,
			Relation: "viewer",
			User:     userStr,
		}

		_, err = srv.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              store.Id,
			AuthorizationModelId: modelV1.AuthorizationModelId,
			Writes:               &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{tuple}},
		})
		if err != nil {
			return // Tuple write failed, skip
		}

		// Step 3: Update to model v2 with DIFFERENT type restriction
		type2Str := string(type2)
		dslV2 := fmt.Sprintf(`
			model
			  schema 1.1
			type user
			type %s
			type %s
			type document
			  relations
			    define viewer: [%s]
		`, type1Str, type2Str, type2Str)

		modelV2DSL, err := transformDSLWithTimeout(dslV2, 5*time.Second)
		if err != nil {
			return // Invalid DSL or timeout, skip
		}

		modelV2, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         store.Id,
			TypeDefinitions: modelV2DSL.GetTypeDefinitions(),
			SchemaVersion:   typesystem.SchemaVersion1_1,
		})
		if err != nil {
			return // Invalid model v2, skip
		}

		// Step 4 & 5: Check with OLD tuple against NEW model
		// This should FAIL because tuple is type1:alice but model expects type2
		checkResp, err := srv.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              store.Id,
			AuthorizationModelId: modelV2.AuthorizationModelId, // Using NEW model
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   docObj,
				Relation: "viewer",
				User:     userStr, // But user is OLD type
			},
		})
		if err != nil {
			return // Check API error, skip
		}

		// VULNERABILITY CHECK: Old tuple with type1 should NOT work with model expecting type2
		if checkResp.Allowed {
			t.Fatalf("VULNERABILITY GHSA-m3q4-7qmj-657m DETECTED!\n"+
				"Model updated from [%s] to [%s]\n"+
				"Old tuple %s still grants access (should be denied due to type mismatch)\n"+
				"Object: %s, User: %s",
				type1Str, type2Str, tuple.String(), docObj, userStr)
		}
	})
}
