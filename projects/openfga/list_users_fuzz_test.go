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
	"runtime"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openfga/openfga/pkg/storage/memory"
)

// FuzzListUsers tests the ListUsers API which finds all users with a specific
// relation to an object. This is a critical new API with complex filtering logic.
func FuzzListUsers(f *testing.F) {
	f.Fuzz(func(t *testing.T, modelDSL []byte, storeID, object, relation, userFilter []byte, configChoice uint8,
		obj1, obj2, obj3, rel1, rel2, rel3, user1, user2, user3, user4, user5 []byte) {
		if len(storeID) == 0 || len(object) == 0 || len(relation) == 0 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		datastore := memory.New()

		svr := newEnhancedFuzzServer(datastore)
		defer func() {
			svr.Close()
			datastore.Close()
			// Force GC to reduce memory pressure from libfuzzer corpus
			runtime.GC()
			time.Sleep(1 * time.Millisecond)
		}()

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

		// Write 8-10 test tuples using fuzzer-provided strings
		tuples := []*openfgav1.TupleKey{
			{Object: string(obj1), Relation: string(rel1), User: string(user1)},
			{Object: string(obj1), Relation: string(rel2), User: string(user2)},
			{Object: string(obj2), Relation: string(rel1), User: string(user3)},
			{Object: string(obj2), Relation: string(rel3), User: string(user4)},
			{Object: string(obj3), Relation: string(rel2), User: string(user5)},
			{Object: string(object), Relation: string(relation), User: string(user1)},
			{Object: string(obj1), Relation: string(relation), User: string(user3)},
			{Object: string(obj2), Relation: string(rel1), User: string(user5)},
			{Object: string(obj3), Relation: string(rel3), User: string(user2)},
			{Object: string(object), Relation: string(rel2), User: string(user4)},
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

		// Build ListUsers request with fuzzer-provided inputs
		listUsersReq := &openfgav1.ListUsersRequest{
			StoreId:              string(storeID),
			AuthorizationModelId: writeModelResp.GetAuthorizationModelId(),
			Object: &openfgav1.Object{
				Type: "document",
				Id:   string(object),
			},
			Relation: string(relation),
			UserFilters: []*openfgav1.UserTypeFilter{
				{Type: string(userFilter)},
			},
		}

		// Add context if condition is present and bit 0 is set
		if configChoice&1 == 1 && len(model.GetConditions()) > 0 {
			listUsersReq.Context, _ = structpb.NewStruct(map[string]interface{}{
				"ip_address": "192.168.1.100",
			})
		}

		resp, err := svr.ListUsers(ctx, listUsersReq)
		if err != nil {
			// Expected for invalid inputs
			return
		}

		// Validate response
		if resp != nil && resp.Users != nil {
			for _, user := range resp.Users {
				if len(user.GetObject().GetType()) == 0 {
					t.Errorf("Invalid user type in response")
				}
			}
		}
	})
}
