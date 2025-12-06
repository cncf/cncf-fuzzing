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
	"strings"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/typesystem"
)

// FuzzRandomAPI sends random requests to all OpenFGA API methods
// This fuzzer tests server robustness against arbitrary inputs
// Enhanced to test schema 1.2, conditions, and various server configurations
func FuzzRandomAPI(f *testing.F) {
	// Seed 1: Basic schema 1.1 model
	f.Add([]byte("model\n  schema 1.1\ntype user\ntype document\n  relations\n    define viewer: [user]"),
		uint8(0), uint8(0), []byte("store1"),
		[]byte("doc1"), []byte("viewer"), []byte("alice"), // Write tuple params
		[]byte("doc2"), []byte("editor"), []byte("bob"), []byte("carol"), // Check params
		[]byte("10"))

	// Seed 2: Schema 1.2 with conditions (triggers further evaluation)
	f.Add([]byte("model\n  schema 1.2\ntype user\ntype document\n  relations\n    define viewer: [user with condition1]\ncondition condition1(x: int) {\n  x < 100\n}"),
		uint8(1), uint8(1), []byte("store2"),
		[]byte("doc1"), []byte("viewer"), []byte("user:alice"),
		[]byte("doc2"), []byte("viewer"), []byte("user:bob"), []byte("user:carol"),
		[]byte("20"))

	// Seed 3: Schema 1.2 with intersection (triggers pipeline path)
	f.Add([]byte("model\n  schema 1.2\ntype user\ntype document\n  relations\n    define owner: [user]\n    define editor: [user]\n    define viewer: owner and editor"),
		uint8(2), uint8(2), []byte("store3"),
		[]byte("document:doc1"), []byte("owner"), []byte("user:alice"),
		[]byte("document:doc2"), []byte("viewer"), []byte("user:bob"), []byte("user:carol"),
		[]byte("15"))

	// Seed 4: Schema 1.2 with exclusion (also triggers pipeline)
	f.Add([]byte("model\n  schema 1.2\ntype user\ntype document\n  relations\n    define member: [user]\n    define blocked: [user]\n    define viewer: member but not blocked"),
		uint8(3), uint8(3), []byte("store4"),
		[]byte("document:doc1"), []byte("member"), []byte("user:alice"),
		[]byte("document:doc2"), []byte("viewer"), []byte("user:bob"), []byte("user:carol"),
		[]byte("25"))

	// Seed 5: Complex schema 1.2 with multiple relations and wildcards
	f.Add([]byte("model\n  schema 1.2\ntype user\ntype group\n  relations\n    define member: [user, user:*]\ntype document\n  relations\n    define parent: [document]\n    define viewer: [group#member] or viewer from parent"),
		uint8(4), uint8(4), []byte("store5"),
		[]byte("document:doc1"), []byte("viewer"), []byte("group:eng#member"),
		[]byte("document:doc2"), []byte("viewer"), []byte("user:bob"), []byte("group:admin#member"),
		[]byte("30"))

	ctx := context.Background()
	datastore := memory.New()
	defer datastore.Close()

	// Use enhanced server with all features enabled
	srv := newEnhancedFuzzServer(datastore)
	defer srv.Close()

	f.Fuzz(func(t *testing.T, modelDSL []byte, methodChoice, schemaChoice, configChoice uint8, storeID,
		// Write tuple parameters
		writeObject, writeRelation, writeUser,
		// Check/Read parameters (different from Write)
		checkObject, checkRelation, checkUser1, _ /* checkUser2 unused */,
		limit []byte) {

		if len(modelDSL) == 0 || len(modelDSL) > 10000 {
			return // Skip empty or extremely large models
		}

		dsl, err := transformDSLWithTimeout(string(modelDSL), 1*time.Second)
		if err != nil {
			return // Not a valid model or timeout, skip
		}

		store, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{
			Name: string(storeID),
		})
		if err != nil {
			return // Store creation failed, skip
		}

		// Choose schema version based on schemaChoice
		// This enables weighted graph and pipeline paths for schema 1.2
		schemaVersion := typesystem.SchemaVersion1_1
		if schemaChoice%2 == 1 {
			schemaVersion = typesystem.SchemaVersion1_2
		}

		// Write the parsed model
		model, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         store.Id,
			TypeDefinitions: dsl.GetTypeDefinitions(),
			SchemaVersion:   schemaVersion,
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
		// checkUser2 removed - not needed after optimization

		// OPTIMIZATION: Generate malformed tuples based on configChoice bits 3-5
		// This triggers parsing error paths and validation branches
		if configChoice&8 != 0 && strings.Contains(checkObjStr, ":") {
			// Remove colon to create malformed object
			checkObjStr = strings.ReplaceAll(checkObjStr, ":", "")
		}
		if configChoice&16 != 0 {
			// Add extra colons for malformed format
			checkObjStr = checkObjStr + ":extra:parts"
		}
		if configChoice&32 != 0 && len(checkUser1Str) > 0 {
			// Empty components
			checkUser1Str = ":" + checkUser1Str
		}

		if writeObjStr == "" || writeRelStr == "" || writeUserStr == "" {
			return
		}

		// OPTIMIZATION: Write multiple tuples to test batch operations
		// Use configChoice bits 6-7 to determine tuple count (1-4 tuples)
		tupleCount := int((configChoice>>6)&0x3) + 1 // Extract bits 6-7, range 1-4
		if tupleCount > 4 {
			tupleCount = 4 // Cap at 4 to avoid excessive writes
		}

		tupleKeys := make([]*openfgav1.TupleKey, 0, tupleCount)
		for i := 0; i < tupleCount; i++ {
			obj := writeObjStr
			if i > 0 && strings.Contains(obj, ":") {
				// Vary object IDs for multiple tuples
				parts := strings.SplitN(obj, ":", 2)
				if len(parts) == 2 {
					obj = fmt.Sprintf("%s:%s_%d", parts[0], parts[1], i)
				} else {
					obj = fmt.Sprintf("%s_%d", obj, i)
				}
			}
			tupleKeys = append(tupleKeys, &openfgav1.TupleKey{
				Object:   obj,
				Relation: writeRelStr,
				User:     writeUserStr,
			})
		}

		// Try to write tuple(s) using Write parameters (may fail if model doesn't support it)
		_, err = srv.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              store.Id,
			AuthorizationModelId: model.AuthorizationModelId,
			Writes: &openfgav1.WriteRequestWrites{
				TupleKeys: tupleKeys,
			},
		})
		if checkObjStr == "" || checkRelStr == "" {
			return
		}

		// Step 4: Choose method based on methodChoice and send random request
		// methodChoice % 6 gives us values 0-5 for 6 different methods
		method := methodChoice % 6

		// Prepare optional context based on configChoice
		var conditionContext *structpb.Struct
		if configChoice&1 != 0 {
			// Add condition context to trigger further evaluation paths
			ctxMap := map[string]interface{}{
				"x": float64(configChoice),
			}
			if ctx, err := structpb.NewStruct(ctxMap); err == nil {
				conditionContext = ctx
			}
		}

		switch method {
		case 0: // BatchCheck - only test one check for speed
			if checkUser1Str == "" {
				return
			}
			req := &openfgav1.BatchCheckRequest{
				StoreId:              store.Id,
				AuthorizationModelId: model.AuthorizationModelId,
				Checks: []*openfgav1.BatchCheckItem{
					{
						TupleKey: &openfgav1.CheckRequestTupleKey{
							Object:   checkObjStr,
							Relation: checkRelStr,
							User:     checkUser1Str,
						},
						Context: conditionContext,
					},
				},
			}
			// Add consistency preference if configChoice bit 2 is set
			if configChoice&2 != 0 {
				req.Consistency = openfgav1.ConsistencyPreference_HIGHER_CONSISTENCY
			}
			srv.BatchCheck(ctx, req)

		case 1: // Check
			if checkUser1Str == "" {
				return
			}
			req := &openfgav1.CheckRequest{
				StoreId:              store.Id,
				AuthorizationModelId: model.AuthorizationModelId,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   checkObjStr,
					Relation: checkRelStr,
					User:     checkUser1Str,
				},
				Context: conditionContext,
			}
			if configChoice&2 != 0 {
				req.Consistency = openfgav1.ConsistencyPreference_HIGHER_CONSISTENCY
			}
			srv.Check(ctx, req)

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
			if checkUser1Str == "" {
				return
			}
			req := &openfgav1.ListObjectsRequest{
				StoreId:              store.Id,
				AuthorizationModelId: model.AuthorizationModelId,
				Type:                 "document",
				Relation:             checkRelStr,
				User:                 checkUser1Str,
				Context:              conditionContext,
			}
			if configChoice&2 != 0 {
				req.Consistency = openfgav1.ConsistencyPreference_HIGHER_CONSISTENCY
			}
			srv.ListObjects(ctx, req)

		case 4: // ListUsers
			req := &openfgav1.ListUsersRequest{
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
				Context: conditionContext,
			}
			if configChoice&2 != 0 {
				req.Consistency = openfgav1.ConsistencyPreference_HIGHER_CONSISTENCY
			}
			srv.ListUsers(ctx, req)

		case 5: // Read with pagination
			// OPTIMIZATION: Use fuzzer-chosen PageSize and follow continuation tokens
			limitInt := int32(10)
			if len(limit) > 0 && limit[0] > 0 && limit[0] < 100 {
				limitInt = int32(limit[0])
			}

			// First page
			resp, err := srv.Read(ctx, &openfgav1.ReadRequest{
				StoreId: store.Id,
				TupleKey: &openfgav1.ReadRequestTupleKey{
					Object:   checkObjStr,
					Relation: checkRelStr,
					User:     checkUser1Str,
				},
				PageSize: wrapperspb.Int32(limitInt),
			})

			// If configChoice bit 1 is set and we have a continuation token, fetch next page
			if err == nil && resp != nil && resp.ContinuationToken != "" && configChoice&2 != 0 {
				srv.Read(ctx, &openfgav1.ReadRequest{
					StoreId:           store.Id,
					ContinuationToken: resp.ContinuationToken,
					PageSize:          wrapperspb.Int32(limitInt),
				})
			}
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
