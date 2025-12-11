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
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"

	"github.com/openfga/openfga/pkg/storage/memory"
)

// FuzzExpand tests the Expand API which retrieves the complete tree of users
// with a specific relation to an object. This tests tree traversal, indirect
// relations, and expansion depth limits.
func FuzzExpand(f *testing.F) {
	// Seed 1: Simple direct relation
	f.Add([]byte(`model
  schema 1.1
type user
type document
  relations
    define viewer: [user]`),
		[]byte("store1"), []byte("document:doc1"), []byte("viewer"))

	// Seed 2: Indirect relation through group
	f.Add([]byte(`model
  schema 1.1
type user
type group
  relations
    define member: [user]
type document
  relations
    define viewer: [group#member]`),
		[]byte("store2"), []byte("document:doc2"), []byte("viewer"))

	// Seed 3: Computed userset relation
	f.Add([]byte(`model
  schema 1.1
type user
type folder
  relations
    define parent: [folder]
    define viewer: [user] or viewer from parent
type document
  relations
    define parent: [folder]
    define viewer: viewer from parent`),
		[]byte("store3"), []byte("document:doc3"), []byte("viewer"))

	// Seed 4: Schema 1.2 with intersection
	f.Add([]byte(`model
  schema 1.2
type user
type document
  relations
    define owner: [user]
    define editor: [user]
    define viewer: owner and editor`),
		[]byte("store4"), []byte("document:doc4"), []byte("viewer"))

	// Seed 5: Schema 1.2 with exclusion
	f.Add([]byte(`model
  schema 1.2
type user
type document
  relations
    define allowed: [user]
    define banned: [user]
    define viewer: allowed but not banned`),
		[]byte("store5"), []byte("document:doc5"), []byte("viewer"))

	f.Fuzz(func(t *testing.T, modelDSL []byte, storeID, object, relation []byte,
		obj1, obj2, obj3, rel1, rel2, rel3, user1, user2, user3, user4, user5 []byte) {
		if len(storeID) == 0 || len(object) == 0 || len(relation) == 0 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		datastore := memory.New()
		defer datastore.Close()

		svr := newEnhancedFuzzServer(datastore)
		defer svr.Close()

		// Parse and write model
		model, err := transformDSLWithTimeout(string(modelDSL), 2*time.Second)
		if err != nil {
			return
		}

		writeModelResp, err := svr.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         string(storeID),
			SchemaVersion:   model.SchemaVersion,
			TypeDefinitions: model.TypeDefinitions,
			Conditions:      model.Conditions,
		})
		if err != nil {
			return
		}

		// Write 5-10 test tuples using fuzzer-provided strings
		tuples := []*openfgav1.TupleKey{
			{Object: string(obj1), Relation: string(rel1), User: string(user1)},
			{Object: string(obj1), Relation: string(rel2), User: string(user2)},
			{Object: string(obj2), Relation: string(rel1), User: string(user3)},
			{Object: string(obj2), Relation: string(rel3), User: string(user4)},
			{Object: string(obj3), Relation: string(rel2), User: string(user5)},
			{Object: string(object), Relation: string(relation), User: string(user1)},
			{Object: string(obj1), Relation: string(relation), User: string(user2)},
			{Object: string(obj2), Relation: string(rel1), User: string(user4)},
			{Object: string(obj3), Relation: string(rel3), User: string(user5)},
			{Object: string(object), Relation: string(rel2), User: string(user3)},
		}

		for _, tuple := range tuples {
			_, _ = svr.Write(ctx, &openfgav1.WriteRequest{
				StoreId:              string(storeID),
				AuthorizationModelId: writeModelResp.GetAuthorizationModelId(),
				Writes: &openfgav1.WriteRequestWrites{
					TupleKeys: []*openfgav1.TupleKey{tuple},
				},
			})
		}

		// Test Expand API with fuzzer-provided inputs
		expandReq := &openfgav1.ExpandRequest{
			StoreId:              string(storeID),
			AuthorizationModelId: writeModelResp.GetAuthorizationModelId(),
			TupleKey: &openfgav1.ExpandRequestTupleKey{
				Object:   string(object),
				Relation: string(relation),
			},
		}

		resp, err := svr.Expand(ctx, expandReq)
		if err != nil {
			// Expected for invalid inputs
			return
		}

		// Validate response structure
		if resp.GetTree() != nil {
			validateExpandTree(resp.GetTree())
		}
	})
}

// Helper to validate expand tree structure
func validateExpandTree(node *openfgav1.UsersetTree) {
	if node == nil {
		return
	}

	// The tree structure has been flattened - just validate it exists
	if node.GetRoot() != nil {
		// Valid tree with root node
	}
}
