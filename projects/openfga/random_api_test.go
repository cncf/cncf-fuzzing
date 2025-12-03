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

	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/typesystem"
)

// FuzzRandomAPI sends random requests to all OpenFGA API methods
// This fuzzer tests server robustness against arbitrary inputs
func FuzzRandomAPI(f *testing.F) {
	f.Add([]byte("model\n  schema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]"),
		uint8(0), []byte("store1"),
		[]byte("doc1"), []byte("viewer"), []byte("alice"), // Write tuple params
		[]byte("doc2"), []byte("editor"), []byte("bob"), []byte("carol"), // Check params
		[]byte("10"))

	f.Fuzz(func(t *testing.T, modelDSL []byte, methodChoice uint8, storeID,
		// Write tuple parameters
		writeObject, writeRelation, writeUser,
		// Check/Read parameters (different from Write)
		checkObject, checkRelation, checkUser1, checkUser2,
		limit []byte) {

		// Step 1 & 2: Try to parse model bytes
		dsl, err := transformDSLWithTimeout(string(modelDSL), 5*time.Second)
		if err != nil {
			return // Not a valid model or timeout, skip
		}

		// Step 3: Set up server
		ctx := context.Background()
		datastore := memory.New()
		defer datastore.Close()

		srv := server.MustNewServerWithOpts(server.WithDatastore(datastore))
		defer srv.Close()

		store, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{
			Name: string(storeID),
		})
		if err != nil {
			return // Store creation failed, skip
		}

		// Write the parsed model
		model, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         store.Id,
			TypeDefinitions: dsl.GetTypeDefinitions(),
			SchemaVersion:   typesystem.SchemaVersion1_1,
		})
		if err != nil {
			return // Model write failed, skip
		}

		// Create strings from Write parameters (separate from Check parameters)
		writeObjStr := string(writeObject)
		writeRelStr := string(writeRelation)
		writeUserStr := string(writeUser)

		// Create strings from Check parameters (independent from Write)
		checkObjStr := string(checkObject)
		checkRelStr := string(checkRelation)
		checkUser1Str := string(checkUser1)
		checkUser2Str := string(checkUser2)

		// Try to write a tuple using Write parameters (may fail if model doesn't support it)
		_, err = srv.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              store.Id,
			AuthorizationModelId: model.AuthorizationModelId,
			Writes: &openfgav1.WriteRequestWrites{
				TupleKeys: []*openfgav1.TupleKey{
					{
						Object:   writeObjStr,
						Relation: writeRelStr,
						User:     writeUserStr,
					},
				},
			},
		})
		if err != nil {
			return
		}

		// Step 4: Choose method based on methodChoice and send random request
		// methodChoice % 7 gives us values 0-6 for 7 different methods
		method := methodChoice % 7

		switch method {
		case 0: // BatchCheck
			srv.BatchCheck(ctx, &openfgav1.BatchCheckRequest{
				StoreId:              store.Id,
				AuthorizationModelId: model.AuthorizationModelId,
				Checks: []*openfgav1.BatchCheckItem{
					{
						TupleKey: &openfgav1.CheckRequestTupleKey{
							Object:   checkObjStr,
							Relation: checkRelStr,
							User:     checkUser1Str,
						},
					},
					{
						TupleKey: &openfgav1.CheckRequestTupleKey{
							Object:   checkObjStr,
							Relation: checkRelStr,
							User:     checkUser2Str,
						},
					},
				},
			})

		case 1: // Check
			srv.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              store.Id,
				AuthorizationModelId: model.AuthorizationModelId,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   checkObjStr,
					Relation: checkRelStr,
					User:     checkUser1Str,
				},
			})

		case 2: // Expand
			srv.Expand(ctx, &openfgav1.ExpandRequest{
				StoreId:              store.Id,
				AuthorizationModelId: model.AuthorizationModelId,
				TupleKey: &openfgav1.ExpandRequestTupleKey{
					Object:   checkObjStr,
					Relation: checkRelStr,
				},
			})

		case 3: // ListObjects
			srv.ListObjects(ctx, &openfgav1.ListObjectsRequest{
				StoreId:              store.Id,
				AuthorizationModelId: model.AuthorizationModelId,
				Type:                 "document",
				Relation:             checkRelStr,
				User:                 checkUser1Str,
			})

		case 4: // ListUsers
			srv.ListUsers(ctx, &openfgav1.ListUsersRequest{
				StoreId:              store.Id,
				AuthorizationModelId: model.AuthorizationModelId,
				Object: &openfgav1.Object{
					Type: "document",
					Id:   checkObjStr,
				},
				Relation: checkRelStr,
				UserFilters: []*openfgav1.UserTypeFilter{
					{
						Type: "user",
					},
				},
			})

		case 5: // Read
			limitInt := int32(10)
			if len(limit) > 0 && limit[0] > 0 && limit[0] < 100 {
				limitInt = int32(limit[0])
			}

			srv.Read(ctx, &openfgav1.ReadRequest{
				StoreId: store.Id,
				TupleKey: &openfgav1.ReadRequestTupleKey{
					Object:   checkObjStr,
					Relation: checkRelStr,
					User:     checkUser1Str,
				},
				PageSize: wrapperspb.Int32(limitInt),
			})
		}

		// Don't check response - we're just testing that server doesn't crash
	})
}

func truncateBytes(b []byte, maxLen int) []byte {
	if len(b) <= maxLen {
		return b
	}
	return b[:maxLen]
}
