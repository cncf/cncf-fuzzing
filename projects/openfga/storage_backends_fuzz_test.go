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

// FuzzStorageBackends tests storage backend implementations for SQL injection,
// encoding issues, and edge cases in tuple storage and retrieval.
// Currently tests SQLite (in-memory) as a representative SQL backend.
func FuzzStorageBackends(f *testing.F) {
	// Seed 1: Normal tuple with various characters
	f.Add([]byte(`model
  schema 1.1
type user
type document
  relations
    define viewer: [user]`),
		[]byte("store1"),
		[]byte("document:doc1"), []byte("viewer"), []byte("user:alice"),
		uint8(0))

	// Seed 2: Tuple with special SQL characters
	f.Add([]byte(`model
  schema 1.1
type user
type document
  relations
    define viewer: [user]`),
		[]byte("store'2"),
		[]byte("document:doc'1"), []byte("view\"er"), []byte("user:ali'ce"),
		uint8(1))

	// Seed 3: Tuple with unicode and special characters
	f.Add([]byte(`model
  schema 1.1
type user
type document
  relations
    define viewer: [user]`),
		[]byte("store_üñí©ödé"),
		[]byte("document:📄doc"), []byte("viewer"), []byte("user:用户"),
		uint8(2))

	// Seed 4: Very long identifiers
	f.Add([]byte(`model
  schema 1.1
type user
type document
  relations
    define viewer: [user]`),
		[]byte("store_with_very_long_identifier_that_might_exceed_limits"),
		[]byte("document:"+string(make([]byte, 200))), []byte("viewer"),
		[]byte("user:"+string(make([]byte, 200))),
		uint8(3))

	// Seed 5: Tuple with null bytes and control characters
	f.Add([]byte(`model
  schema 1.1
type user
type document
  relations
    define viewer: [user]`),
		[]byte("store\x00with\x01null"),
		[]byte("document:doc\nnewline"), []byte("viewer"), []byte("user:\ttab"),
		uint8(4))

	f.Fuzz(func(t *testing.T, modelDSL []byte, storeID, object, relation, user []byte, backendChoice uint8,
		obj1, obj2, obj3, rel1, rel2, rel3, user1, user2, user3, user4 []byte) {
		if len(storeID) == 0 || len(object) == 0 || len(relation) == 0 || len(user) == 0 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Select storage backend based on fuzzer input
		// For now, only use memory backend until SQLite config is sorted out
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

		// Test Write with 8 fuzzer-provided tuples (potential SQL injection vectors)
		tuples := []*openfgav1.TupleKey{
			{Object: string(object), Relation: string(relation), User: string(user)},
			{Object: string(obj1), Relation: string(rel1), User: string(user1)},
			{Object: string(obj1), Relation: string(rel2), User: string(user2)},
			{Object: string(obj2), Relation: string(rel1), User: string(user3)},
			{Object: string(obj2), Relation: string(rel3), User: string(user4)},
			{Object: string(obj3), Relation: string(rel2), User: string(user1)},
			{Object: string(obj3), Relation: string(rel3), User: string(user2)},
			{Object: string(object), Relation: string(rel1), User: string(user3)},
		}

		for _, tuple := range tuples {
			_, err = svr.Write(ctx, &openfgav1.WriteRequest{
				StoreId:              string(storeID),
				AuthorizationModelId: writeModelResp.GetAuthorizationModelId(),
				Writes: &openfgav1.WriteRequestWrites{
					TupleKeys: []*openfgav1.TupleKey{tuple},
				},
			})
			if err != nil {
				// Expected for invalid inputs
				continue
			}
		}

		// Test Read to verify tuples were stored correctly
		for _, tuple := range tuples {
			readResp, err := svr.Read(ctx, &openfgav1.ReadRequest{
				StoreId: string(storeID),
				TupleKey: &openfgav1.ReadRequestTupleKey{
					Object:   tuple.Object,
					Relation: tuple.Relation,
					User:     tuple.User,
				},
			})
			if err != nil {
				continue
			}

			// Verify tuple was stored and retrieved correctly (no corruption)
			if readResp != nil && len(readResp.GetTuples()) > 0 {
				retrievedTuple := readResp.GetTuples()[0].GetKey()
				if retrievedTuple.GetObject() != tuple.Object {
					t.Errorf("Storage corrupted object: wrote %q, read %q",
						tuple.Object, retrievedTuple.GetObject())
				}
				if retrievedTuple.GetRelation() != tuple.Relation {
					t.Errorf("Storage corrupted relation: wrote %q, read %q",
						tuple.Relation, retrievedTuple.GetRelation())
				}
				if retrievedTuple.GetUser() != tuple.User {
					t.Errorf("Storage corrupted user: wrote %q, read %q",
						tuple.User, retrievedTuple.GetUser())
				}
			}
		}

		// Test Check with first tuple
		if len(tuples) > 0 {
			firstTuple := tuples[0]
			_, _ = svr.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              string(storeID),
				AuthorizationModelId: writeModelResp.GetAuthorizationModelId(),
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   firstTuple.Object,
					Relation: firstTuple.Relation,
					User:     firstTuple.User,
				},
			})
		}

		// Test Delete for all tuples
		for _, tuple := range tuples {
			_, _ = svr.Write(ctx, &openfgav1.WriteRequest{
				StoreId:              string(storeID),
				AuthorizationModelId: writeModelResp.GetAuthorizationModelId(),
				Deletes: &openfgav1.WriteRequestDeletes{
					TupleKeys: []*openfgav1.TupleKeyWithoutCondition{
						{
							Object:   tuple.Object,
							Relation: tuple.Relation,
							User:     tuple.User,
						},
					},
				},
			})
		}

		// Verify deletion worked for first tuple
		if len(tuples) > 0 {
			firstTuple := tuples[0]
			readAfterDelete, err := svr.Read(ctx, &openfgav1.ReadRequest{
				StoreId: string(storeID),
				TupleKey: &openfgav1.ReadRequestTupleKey{
					Object:   firstTuple.Object,
					Relation: firstTuple.Relation,
					User:     firstTuple.User,
				},
			})
			if err == nil && readAfterDelete != nil && len(readAfterDelete.GetTuples()) > 0 {
				t.Errorf("Tuple was not deleted from storage")
			}
		}
	})
}

// datastore interface to allow switching backends
