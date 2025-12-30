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
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/openfga/openfga/pkg/storage/memory"
)

// FuzzRead tests the Read API which queries tuples from the store.
// Tests pagination, filtering, and edge cases in tuple retrieval.
func FuzzRead(f *testing.F) {
	f.Fuzz(func(t *testing.T, modelDSL []byte, storeID, object, relation, user []byte, pageSize uint8,
		obj1, obj2, obj3, obj4, rel1, rel2, rel3, user1, user2, user3, user4, user5 []byte) {
		if len(storeID) == 0 {
			return
		}

		// Limit page size to reasonable values
		if pageSize == 0 {
			pageSize = 1
		}
		if pageSize > 50 {
			pageSize = 50
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

		// Write 10 test tuples using fuzzer-provided strings
		tuples := []*openfgav1.TupleKey{
			{Object: string(obj1), Relation: string(rel1), User: string(user1)},
			{Object: string(obj1), Relation: string(rel2), User: string(user2)},
			{Object: string(obj2), Relation: string(rel1), User: string(user3)},
			{Object: string(obj2), Relation: string(rel3), User: string(user4)},
			{Object: string(obj3), Relation: string(rel2), User: string(user5)},
			{Object: string(obj4), Relation: string(rel1), User: string(user1)},
			{Object: string(object), Relation: string(relation), User: string(user)},
			{Object: string(obj1), Relation: string(relation), User: string(user3)},
			{Object: string(obj3), Relation: string(rel3), User: string(user2)},
			{Object: string(obj2), Relation: string(rel2), User: string(user5)},
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

		// Build Read request with fuzzer-provided filters
		readReq := &openfgav1.ReadRequest{
			StoreId: string(storeID),
			TupleKey: &openfgav1.ReadRequestTupleKey{
				Object:   string(object),
				Relation: string(relation),
				User:     string(user),
			},
			PageSize: wrapperspb.Int32(int32(pageSize)),
		}

		// Test Read API
		resp, err := svr.Read(ctx, readReq)
		if err != nil {
			// Expected for invalid inputs
			return
		}

		// Validate response
		if resp != nil {
			if len(resp.GetTuples()) > int(pageSize) {
				t.Errorf("Read returned more tuples than page size: got %d, limit %d",
					len(resp.GetTuples()), pageSize)
			}

			// Validate tuple structure
			for _, tuple := range resp.GetTuples() {
				if tuple.GetKey() == nil {
					t.Errorf("Read returned tuple with nil key")
					continue
				}
				if len(tuple.GetKey().GetObject()) == 0 {
					t.Errorf("Read returned tuple with empty object")
				}
				if len(tuple.GetKey().GetRelation()) == 0 {
					t.Errorf("Read returned tuple with empty relation")
				}
				if len(tuple.GetKey().GetUser()) == 0 {
					t.Errorf("Read returned tuple with empty user")
				}
			}

			// Test pagination if continuation token is present
			if resp.GetContinuationToken() != "" {
				readReq.ContinuationToken = resp.GetContinuationToken()
				_, _ = svr.Read(ctx, readReq)
			}
		}
	})
}
