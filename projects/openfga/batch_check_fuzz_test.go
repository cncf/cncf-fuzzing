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
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openfga/openfga/pkg/storage/memory"
)

// FuzzBatchCheck tests the BatchCheck API which performs multiple authorization
// checks in a single request. Tests parallel processing, error aggregation,
// and consistency across multiple checks.
func FuzzBatchCheck(f *testing.F) {
	f.Fuzz(func(t *testing.T, modelDSL []byte, storeID []byte,
		obj1, rel1, user1, obj2, rel2, user2 []byte, batchSize uint8,
		obj3, obj4, rel3, rel4, user3, user4, user5 []byte) {

		if len(storeID) == 0 || batchSize == 0 {
			return
		}

		// Limit batch size to prevent DoS
		if batchSize > 20 {
			batchSize = 20
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

		// Write 8 test tuples using all fuzzer-provided strings
		tuples := []*openfgav1.TupleKey{
			{Object: string(obj1), Relation: string(rel1), User: string(user1)},
			{Object: string(obj1), Relation: string(rel2), User: string(user2)},
			{Object: string(obj2), Relation: string(rel1), User: string(user3)},
			{Object: string(obj2), Relation: string(rel3), User: string(user4)},
			{Object: string(obj3), Relation: string(rel2), User: string(user5)},
			{Object: string(obj3), Relation: string(rel4), User: string(user1)},
			{Object: string(obj4), Relation: string(rel1), User: string(user2)},
			{Object: string(obj4), Relation: string(rel3), User: string(user3)},
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

		// Build batch of check requests
		checks := make([]*openfgav1.BatchCheckItem, 0, batchSize)

		// Add fuzzer-provided checks
		if len(obj1) > 0 && len(rel1) > 0 && len(user1) > 0 {
			checks = append(checks, &openfgav1.BatchCheckItem{
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   string(obj1),
					Relation: string(rel1),
					User:     string(user1),
				},
			})
		}

		if len(obj2) > 0 && len(rel2) > 0 && len(user2) > 0 && batchSize > 1 {
			checks = append(checks, &openfgav1.BatchCheckItem{
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   string(obj2),
					Relation: string(rel2),
					User:     string(user2),
				},
			})
		}

		// Fill remaining batch with variations
		objects := []string{"document:doc1", "document:doc2", "document:doc3"}
		relations := []string{"viewer", "editor", "allowed"}
		users := []string{"user:alice", "user:bob", "user:carol"}

		for i := len(checks); i < int(batchSize); i++ {
			check := &openfgav1.BatchCheckItem{
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   objects[i%len(objects)],
					Relation: relations[i%len(relations)],
					User:     users[i%len(users)],
				},
			}

			// Add context if conditions present
			if len(model.GetConditions()) > 0 && i%2 == 0 {
				check.Context, _ = structpb.NewStruct(map[string]interface{}{
					"x": int64(i * 10),
				})
			}

			checks = append(checks, check)
		}

		if len(checks) == 0 {
			return
		}

		// Test BatchCheck API
		batchCheckReq := &openfgav1.BatchCheckRequest{
			StoreId:              string(storeID),
			AuthorizationModelId: writeModelResp.GetAuthorizationModelId(),
			Checks:               checks,
		}

		resp, err := svr.BatchCheck(ctx, batchCheckReq)
		if err != nil {
			// Expected for invalid inputs
			return
		}

		// Validate response
		if resp != nil {
			if len(resp.GetResult()) != len(checks) {
				t.Errorf("BatchCheck returned wrong number of results: got %d, expected %d",
					len(resp.GetResult()), len(checks))
			}

		// Validate individual check results
		for idx, result := range resp.GetResult() {
			if result == nil {
				t.Errorf("BatchCheck result[%v] is nil", idx)
				continue
			}				// Check result should have either allowed status or error
				if result.GetAllowed() == false && result.GetError() == nil {
					// This is valid - check returned false without error
				}
			}
		}
	})
}
