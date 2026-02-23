// Copyright 2026 the cncf-fuzzing authors
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
	parser "github.com/openfga/language/pkg/go/transformer"

	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/tuple"
	"github.com/openfga/openfga/pkg/typesystem"
)

// FuzzListUsersConsistency tests that ListUsers results are consistent with Check.
// The existing FuzzListUsers has 0% coverage on list_users_rpc.go because it writes
// tuples to arbitrary types but hardcodes Type: "document" in queries, so the expansion
// algorithm never executes.
//
// This fuzzer uses a fixed model with known types (document, folder, group, user) and
// writes matching tuples so the expansion algorithm actually runs. It then cross-validates
// every returned user against the Check API.
//
// The model exercises ALL expansion paths:
// - Direct assignment (editor, viewer, folder.viewer)
// - Wildcards (user:* on member, viewer)
// - Userset reference (group#member)
// - Union (or editor or viewer from parent)
// - Tuple-to-userset (viewer from parent)
// - Exclusion (but not blocked)
func FuzzListUsersConsistency(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		docID, folderID, groupID string,
		userID1, userID2, userID3 string,
		tupleConfig uint8,
		queryRelation uint8) {

		// Validate inputs
		if docID == "" || folderID == "" || groupID == "" {
			return
		}
		if userID1 == "" || userID2 == "" || userID3 == "" {
			return
		}

		// Validate that constructed object/user strings are valid
		docObj := fmt.Sprintf("document:%s", docID)
		folderObj := fmt.Sprintf("folder:%s", folderID)
		groupObj := fmt.Sprintf("group:%s", groupID)
		user1 := fmt.Sprintf("user:%s", userID1)
		user2 := fmt.Sprintf("user:%s", userID2)
		user3 := fmt.Sprintf("user:%s", userID3)

		if !tuple.IsValidObject(docObj) || !tuple.IsValidObject(folderObj) || !tuple.IsValidObject(groupObj) {
			return
		}
		if !tuple.IsValidUser(user1) || !tuple.IsValidUser(user2) || !tuple.IsValidUser(user3) {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		datastore := memory.New()
		srv := newEnhancedFuzzServer(datastore)
		defer func() {
			srv.Close()
			datastore.Close()
		}()

		store, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz"})
		if err != nil {
			return
		}

		// Fixed model exercising all expansion paths including intersection
		dsl := parser.MustTransformDSLToProto(`
			model
			  schema 1.1
			type user
			type group
			  relations
			    define member: [user, user:*]
			type folder
			  relations
			    define viewer: [user]
			type document
			  relations
			    define parent: [folder]
			    define editor: [user]
			    define viewer: [user, user:*, group#member] or editor or viewer from parent
			    define blocked: [user, user:*]
			    define can_view: viewer but not blocked
			    define can_edit: editor and viewer
		`)

		model, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         store.Id,
			TypeDefinitions: dsl.GetTypeDefinitions(),
			SchemaVersion:   typesystem.SchemaVersion1_1,
		})
		if err != nil {
			return
		}
		modelID := model.AuthorizationModelId

		// Write tuples based on tupleConfig bits
		type tupleSpec struct {
			object   string
			relation string
			user     string
			bit      uint8
		}

		specs := []tupleSpec{
			{docObj, "editor", user1, 0},                          // bit 0
			{docObj, "viewer", user2, 1},                          // bit 1
			{docObj, "viewer", "user:*", 2},                       // bit 2
			{groupObj, "member", user3, 3},                        // bit 3
			{docObj, "viewer", groupObj + "#member", 4},           // bit 4
			{folderObj, "viewer", user1, 5},                       // bit 5
			{docObj, "parent", folderObj, 6},                      // bit 6
			{docObj, "blocked", "user:*", 7},                      // bit 7: wildcard block
		}

		writtenTuples := []string{}
		for _, spec := range specs {
			if tupleConfig&(1<<spec.bit) == 0 {
				continue
			}
			_, err := srv.Write(ctx, &openfgav1.WriteRequest{
				StoreId:              store.Id,
				AuthorizationModelId: modelID,
				Writes: &openfgav1.WriteRequestWrites{
					TupleKeys: []*openfgav1.TupleKey{{
						Object:   spec.object,
						Relation: spec.relation,
						User:     spec.user,
					}},
				},
			})
			if err == nil {
				writtenTuples = append(writtenTuples, fmt.Sprintf("(%s, %s, %s)", spec.object, spec.relation, spec.user))
			}
		}

		// Select query relation
		var queryRel string
		switch queryRelation % 4 {
		case 0:
			queryRel = "viewer"
		case 1:
			queryRel = "editor"
		case 2:
			queryRel = "can_view"
		case 3:
			queryRel = "can_edit"
		}

		// Call ListUsers
		listResp, err := srv.ListUsers(ctx, &openfgav1.ListUsersRequest{
			StoreId:              store.Id,
			AuthorizationModelId: modelID,
			Object: &openfgav1.Object{
				Type: "document",
				Id:   docID,
			},
			Relation: queryRel,
			UserFilters: []*openfgav1.UserTypeFilter{
				{Type: "user"},
			},
		})
		if err != nil {
			return
		}

		// Cross-validate: every user returned by ListUsers must be allowed by Check
		if listResp != nil && listResp.Users != nil {
			for _, returnedUser := range listResp.Users {
				userObj := returnedUser.GetObject()
				wildcard := returnedUser.GetWildcard()

				var checkUserStr string
				if userObj != nil && userObj.Type != "" && userObj.Id != "" {
					checkUserStr = fmt.Sprintf("%s:%s", userObj.Type, userObj.Id)
				} else if wildcard != nil && wildcard.Type != "" {
					// Wildcard user - skip Check validation since Check with user:*
					// has different semantics than Check with a concrete user
					continue
				} else {
					continue
				}

				checkResp, err := srv.Check(ctx, &openfgav1.CheckRequest{
					StoreId:              store.Id,
					AuthorizationModelId: modelID,
					TupleKey: &openfgav1.CheckRequestTupleKey{
						Object:   docObj,
						Relation: queryRel,
						User:     checkUserStr,
					},
				})
				if err != nil {
					continue
				}

				if !checkResp.Allowed {
					t.Fatalf("INCONSISTENCY: ListUsers returned %s but Check denied!\n"+
						"Document: %s\n"+
						"Relation: %s\n"+
						"ListUsers returned user: %s\n"+
						"Check with same user returned: Allowed=false\n"+
						"tupleConfig: %08b\n"+
						"Written tuples: %v",
						checkUserStr, docObj, queryRel, checkUserStr,
						tupleConfig, writtenTuples)
				}
			}
		}
	})
}
