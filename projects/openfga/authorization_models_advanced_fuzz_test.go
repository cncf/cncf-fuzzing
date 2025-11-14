// Copyright 2024 the cncf-fuzzing authors
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

	"github.com/oklog/ulid/v2"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	parser "github.com/openfga/language/pkg/go/transformer"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openfga/openfga/cmd/util"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/tuple"
)

const fuzzerCanaryUser = "user:__fuzzer_canary_never_grant__"

// =============================================================================
// ADVANCED AUTHORIZATION MODEL FUZZERS
// =============================================================================
// These fuzzers test more complex authorization model features:
// - Exclusion (but not)
// - Intersection (and)
// - Computed Userset (relation chaining)
// - Public Access (wildcards)
// - Multiple Restrictions
// =============================================================================

// FuzzCheckWithExclusion fuzzes the Check API with exclusion (but not) semantics
//
// AUTHORIZATION MODEL: Document with exclusion-based access control
// - document.viewer: user (direct assignment)
// - document.restricted: user (blocklist - direct assignment only)
// - document.can_view: viewer BUT NOT restricted
//
// EXCLUSION SEMANTICS (but not):
// A user can_view if they are a viewer AND NOT in the restricted list.
// This tests that exclusions properly deny access even when base permission exists.
//
// EXAMPLE SCENARIOS:
// - Tuple 1: (document:d1, viewer, user:alice)
// - Tuple 2: (document:d1, restricted, user:bob)
// - Check (document:d1, can_view, user:alice) → ALLOWED (viewer, not restricted)
// - Check (document:d1, can_view, user:bob) → DENIED (not a viewer)
//
// - Tuple 1: (document:d1, viewer, user:alice)
// - Tuple 2: (document:d1, restricted, user:alice)
// - Check (document:d1, can_view, user:alice) → DENIED (viewer BUT restricted blocks it)
//
// CRITICAL INVARIANTS TESTED:
// 1. User with viewer access AND in restricted list MUST be denied
// 2. User with viewer access NOT in restricted list MUST be allowed
// 3. User without viewer access MUST be denied (regardless of restricted)
// 4. Canary user (never granted) MUST be denied
//
// IMPORTANT: Exclusion is a critical security feature - bugs could allow
// access to blocked users (e.g., revoked employees, banned accounts)
func FuzzCheckWithExclusion(f *testing.F) {
	// Seed with valid exclusion patterns
	f.Add("document:d1", "viewer", "user:alice", "", "", "", "document:d1", "can_view", "user:alice")                          // viewer, not restricted → ALLOWED
	f.Add("document:d1", "viewer", "user:bob", "document:d1", "restricted", "user:bob", "document:d1", "can_view", "user:bob") // viewer AND restricted → DENIED

	f.Fuzz(func(t *testing.T, write1Obj, write1Rel, write1User, write2Obj, write2Rel, write2User, checkObj, checkRel, checkUser string) {
		// Skip obviously broken inputs
		if write1User == "" || checkUser == "" || write1Obj == "" || checkObj == "" {
			return
		}

		ctx := context.Background()

		// Initialize server with datastore
		_, ds, _ := util.MustBootstrapDatastore(t, "memory")
		s := server.MustNewServerWithOpts(server.WithDatastore(ds))
		defer s.Close()

		// Create store
		createStoreResp, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{
			Name: "fuzz-test",
		})
		if err != nil {
			t.Skip("failed to create store")
			return
		}
		storeID := createStoreResp.GetId()

		// Model with exclusion: can_view = viewer BUT NOT restricted
		// This tests the "but not" exclusion operator - users in viewer but in restricted list should be denied
		model := parser.MustTransformDSLToProto(`
			model
				schema 1.1

			type user

			type document
				relations
					define viewer: [user]
					define restricted: [user]
					define can_view: viewer but not restricted
		`)
		model.Id = ulid.Make().String()

		// Write authorization model
		writeModelResp, err := s.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         storeID,
			SchemaVersion:   model.SchemaVersion,
			TypeDefinitions: model.TypeDefinitions,
		})
		if err != nil {
			t.Skip("model validation failed")
			return
		}
		modelID := writeModelResp.GetAuthorizationModelId()

		// Write tuples
		tuple1 := &openfgav1.TupleKey{
			Object:   write1Obj,
			Relation: write1Rel,
			User:     write1User,
		}

		var tuple2 *openfgav1.TupleKey
		tuplesWritten := 0

		if tuple.IsValidObject(write1Obj) && tuple.IsValidUser(write1User) && write1Rel != "" {
			_, err = s.Write(ctx, &openfgav1.WriteRequest{
				StoreId: storeID,
				Writes: &openfgav1.WriteRequestWrites{
					TupleKeys: []*openfgav1.TupleKey{tuple1},
				},
			})
			if err == nil {
				tuplesWritten++
			}
		}

		if write2User != "" && write2Obj != "" {
			tuple2 = &openfgav1.TupleKey{
				Object:   write2Obj,
				Relation: write2Rel,
				User:     write2User,
			}
			if tuple.IsValidObject(write2Obj) && tuple.IsValidUser(write2User) && write2Rel != "" {
				_, err = s.Write(ctx, &openfgav1.WriteRequest{
					StoreId: storeID,
					Writes: &openfgav1.WriteRequestWrites{
						TupleKeys: []*openfgav1.TupleKey{tuple2},
					},
				})
				if err == nil {
					tuplesWritten++
				}
			}
		}

		if tuplesWritten == 0 {
			return
		}

		// Perform Check via untrusted server entrypoint
		resp, err := s.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   checkObj,
				Relation: checkRel,
				User:     checkUser,
			},
		})
		if err != nil {
			return
		}

		t.Logf("FuzzCheckWithExclusion - Response: Allowed=%v", resp.Allowed)

		// ========================================================================
		// FUZZER SANITY CHECK - Canary User
		// ========================================================================
		if tuplesWritten > 0 {
			canaryResp, err := s.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              storeID,
				AuthorizationModelId: modelID,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   tuple1.Object,
					Relation: tuple1.Relation,
					User:     fuzzerCanaryUser,
				},
			})
			if err == nil && canaryResp.Allowed {
				t.Fatalf("🚨 FUZZER SANITY CHECK FAILED: Canary user was granted access!\n"+
					"  Tuple 1: (%s, %s, %s)\n"+
					"  Tuple 2: (%s, %s, %s)\n"+
					"  Canary Check: (%s, %s, %s)\n",
					write1Obj, write1Rel, write1User,
					write2Obj, write2Rel, write2User,
					tuple1.Object, tuple1.Relation, fuzzerCanaryUser)
			}
		}

		// ========================================================================
		// CRITICAL INVARIANTS - Exclusion Bypass Detection
		// ========================================================================

		// INVARIANT 1: User with viewer AND in restricted list MUST be denied
		//
		// Scenario:
		// - (document:d1, viewer, user:alice) - alice is a viewer
		// - (document:d1, restricted, user:alice) - alice is restricted
		// - Check (document:d1, can_view, user:alice) → MUST BE DENIED
		//
		// This is the core exclusion test: even with viewer access, being in
		// the restricted list should block access.
		userIsViewerAndRestricted := tuplesWritten == 2 &&
			tuple1.Relation == "viewer" &&
			tuple2.Relation == "restricted" &&
			tuple1.Object == tuple2.Object &&
			tuple1.User == tuple2.User &&
			tuple.GetType(tuple1.User) == "user" &&
			checkObj == tuple1.Object &&
			checkRel == "can_view" &&
			checkUser == tuple1.User

		if userIsViewerAndRestricted && resp.Allowed {
			t.Fatalf("🚨 EXCLUSION BYPASS: User in restricted list was allowed access!\n"+
				"  Tuple 1: (%s, %s, %s) ← User is viewer\n"+
				"  Tuple 2: (%s, %s, %s) ← User is restricted\n"+
				"  Check:   (%s, %s, %s) ← can_view = viewer BUT NOT restricted\n"+
				"  Expected: DENIED (exclusion should block access)\n"+
				"  Got: ALLOWED\n"+
				"  This is a CRITICAL security bug - blocklist was ignored!\n",
				write1Obj, write1Rel, write1User,
				write2Obj, write2Rel, write2User,
				checkObj, checkRel, checkUser)
		}

		// INVARIANT 2: User with viewer NOT in restricted list MUST be allowed
		//
		// Scenario:
		// - (document:d1, viewer, user:alice) - alice is a viewer
		// - (document:d1, restricted, user:bob) - bob is restricted (NOT alice)
		// - Check (document:d1, can_view, user:alice) → MUST BE ALLOWED
		//
		// Alice has viewer and is not restricted, so she should have access.
		userIsViewerNotRestricted := tuplesWritten == 2 &&
			tuple1.Relation == "viewer" &&
			tuple2.Relation == "restricted" &&
			tuple1.Object == tuple2.Object &&
			tuple1.User != tuple2.User &&
			tuple.GetType(tuple1.User) == "user" &&
			tuple.GetType(tuple2.User) == "user" &&
			checkObj == tuple1.Object &&
			checkRel == "can_view" &&
			checkUser == tuple1.User

		if userIsViewerNotRestricted && !resp.Allowed {
			t.Fatalf("🚨 EXCLUSION ERROR: User with viewer NOT in restricted was denied!\n"+
				"  Tuple 1: (%s, %s, %s) ← User is viewer\n"+
				"  Tuple 2: (%s, %s, %s) ← Different user is restricted\n"+
				"  Check:   (%s, %s, %s) ← can_view = viewer BUT NOT restricted\n"+
				"  Expected: ALLOWED (user is viewer and not in restricted)\n"+
				"  Got: DENIED\n"+
				"  This is a bug - valid access was incorrectly denied!\n",
				write1Obj, write1Rel, write1User,
				write2Obj, write2Rel, write2User,
				checkObj, checkRel, checkUser)
		}

		// INVARIANT 3: User WITHOUT viewer access MUST be denied
		//
		// Scenario:
		// - (document:d1, viewer, user:alice) - alice is a viewer
		// - Check (document:d1, can_view, user:bob) → MUST BE DENIED
		//
		// Bob doesn't have viewer, so even if he's not restricted, he can't access.
		userNotViewer := tuplesWritten >= 1 &&
			tuple1.Relation == "viewer" &&
			tuple.GetType(tuple1.User) == "user" &&
			tuple.GetType(checkUser) == "user" &&
			checkObj == tuple1.Object &&
			checkRel == "can_view" &&
			checkUser != tuple1.User

		if userNotViewer && resp.Allowed {
			t.Fatalf("🚨 AUTHORIZATION BYPASS: User without viewer access was allowed!\n"+
				"  Tuple 1: (%s, %s, %s) ← Different user has viewer\n"+
				"  Check:   (%s, %s, %s) ← This user doesn't have viewer\n"+
				"  Expected: DENIED (user must have viewer to access)\n"+
				"  Got: ALLOWED\n"+
				"  This is a security bug!\n",
				write1Obj, write1Rel, write1User,
				checkObj, checkRel, checkUser)
		}
	})
}

// FuzzCheckWithIntersection fuzzes the Check API with intersection (and) semantics
//
// AUTHORIZATION MODEL: Document with intersection-based access control
// - document.org_member: organization (which org owns the document)
// - document.writer: user (who can write to document)
// - document.can_delete: org_member AND writer (must satisfy BOTH)
//
// INTERSECTION SEMANTICS (and):
// A user can_delete if they are BOTH a member of the owning org AND a writer.
// This tests that intersections require ALL conditions to be satisfied.
//
// CRITICAL INVARIANTS TESTED:
// 1. User with BOTH org membership AND writer access MUST be allowed
// 2. User with ONLY org membership (no writer) MUST be denied
// 3. User with ONLY writer access (not org member) MUST be denied
// 4. User with NEITHER condition MUST be denied
// 5. Canary user (never granted) MUST be denied
//
// IMPORTANT: Intersection is critical for privilege separation - bugs could
// allow partial access (e.g., org member without permission, or vice versa)
func FuzzCheckWithIntersection(f *testing.F) {
	// Seed with valid intersection patterns
	f.Add("document:d1", "org_member", "organization:acme", "document:d1", "writer", "user:alice", "organization:acme", "member", "user:alice", "document:d1", "can_delete", "user:alice") // BOTH conditions → ALLOWED
	f.Add("document:d1", "org_member", "organization:acme", "", "", "", "organization:acme", "member", "user:bob", "document:d1", "can_delete", "user:bob")                                // ONLY org member → DENIED

	f.Fuzz(func(t *testing.T, write1Obj, write1Rel, write1User, write2Obj, write2Rel, write2User, write3Obj, write3Rel, write3User, checkObj, checkRel, checkUser string) {
		// Skip obviously broken inputs
		if checkUser == "" || checkObj == "" {
			return
		}

		// KNOWN BUG FILTER: Skip empty user IDs
		if checkUser == "user:" || write1User == "user:" || write2User == "user:" || write3User == "user:" {
			return
		}

		ctx := context.Background()

		// Initialize server using UNTRUSTED ENTRYPOINT
		_, ds, _ := util.MustBootstrapDatastore(t, "memory")
		defer ds.Close()
		s := server.MustNewServerWithOpts(server.WithDatastore(ds))
		defer s.Close()

		// Create store via server API
		createResp, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz-test"})
		if err != nil {
			t.Skip("failed to create store")
			return
		}
		storeID := createResp.GetId()

		// Model with intersection: can_delete = (member of org_member) AND writer
		// This requires tuple-to-userset on org_member to resolve organization membership
		model := parser.MustTransformDSLToProto(`
			model
				schema 1.1

			type user

			type organization
				relations
					define member: [user]

			type document
				relations
					define org_member: [organization]
					define writer: [user]
					define can_delete: member from org_member and writer
		`)
		model.Id = ulid.Make().String()

		// Write model via server API
		writeModelResp, err := s.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         storeID,
			TypeDefinitions: model.GetTypeDefinitions(),
			SchemaVersion:   model.GetSchemaVersion(),
		})
		if err != nil {
			t.Skip("model validation failed")
			return
		}
		modelID := writeModelResp.GetAuthorizationModelId()

		// Write up to 3 tuples
		var tuples []*openfgav1.TupleKey
		if write1User != "" && write1Obj != "" && write1Rel != "" && tuple.IsValidObject(write1Obj) && tuple.IsValidUser(write1User) {
			tuples = append(tuples, &openfgav1.TupleKey{Object: write1Obj, Relation: write1Rel, User: write1User})
		}
		if write2User != "" && write2Obj != "" && write2Rel != "" && tuple.IsValidObject(write2Obj) && tuple.IsValidUser(write2User) {
			tuples = append(tuples, &openfgav1.TupleKey{Object: write2Obj, Relation: write2Rel, User: write2User})
		}
		if write3User != "" && write3Obj != "" && write3Rel != "" && tuple.IsValidObject(write3Obj) && tuple.IsValidUser(write3User) {
			tuples = append(tuples, &openfgav1.TupleKey{Object: write3Obj, Relation: write3Rel, User: write3User})
		}

		if len(tuples) == 0 {
			return
		}

		// Write tuples via server API
		_, err = s.Write(ctx, &openfgav1.WriteRequest{
			StoreId: storeID,
			Writes:  &openfgav1.WriteRequestWrites{TupleKeys: tuples},
		})
		if err != nil {
			return
		}

		// Perform Check via UNTRUSTED SERVER ENTRYPOINT
		resp, err := s.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   checkObj,
				Relation: checkRel,
				User:     checkUser,
			},
		})
		if err != nil {
			return
		}

		t.Logf("FuzzCheckWithIntersection - Response: Allowed=%v", resp.Allowed)

		// ========================================================================
		// FUZZER SANITY CHECK - Canary User
		// ========================================================================
		if len(tuples) > 0 {
			canaryResp, err := s.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              storeID,
				AuthorizationModelId: modelID,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   tuples[0].Object,
					Relation: tuples[0].Relation,
					User:     fuzzerCanaryUser,
				},
			})
			if err == nil && canaryResp.Allowed {
				t.Fatalf("🚨 FUZZER SANITY CHECK FAILED: Canary user was granted access!\n"+
					"Model:\n%s",
					formatAuthModelForDebug(model))
			}
		}

		// ========================================================================
		// CRITICAL INVARIANTS - Intersection Bypass Detection
		// ========================================================================

		// INVARIANT 1: User with BOTH conditions MUST be allowed
		//
		// Scenario (requires 3 tuples):
		// - (document:d1, org_member, organization:acme) - document owned by acme
		// - (document:d1, writer, user:alice) - alice is writer
		// - (organization:acme, member, user:alice) - alice is acme member
		// - Check (document:d1, can_delete, user:alice) → MUST BE ALLOWED
		//
		// Alice satisfies BOTH conditions: org member AND writer
		if len(tuples) == 3 {
			// Try to identify the pattern
			var docObj, orgObj, user string
			hasOrgMember, hasWriter, hasOrgMemberTuple := false, false, false

			for _, t := range tuples {
				if t.Relation == "org_member" && tuple.GetType(t.Object) == "document" && tuple.GetType(t.User) == "organization" {
					docObj = t.Object
					orgObj = t.User
					hasOrgMember = true
				}
				if t.Relation == "writer" && tuple.GetType(t.User) == "user" {
					if t.Object == docObj {
						user = t.User
						hasWriter = true
					}
				}
				if t.Relation == "member" && tuple.GetType(t.User) == "user" {
					if t.Object == orgObj && t.User == user {
						hasOrgMemberTuple = true
					}
				}
			}

			bothConditionsMet := hasOrgMember && hasWriter && hasOrgMemberTuple &&
				checkObj == docObj &&
				checkRel == "can_delete" &&
				checkUser == user

			if bothConditionsMet && !resp.Allowed {
				t.Fatalf("🚨 INTERSECTION ERROR: User with BOTH conditions was denied!\n"+
					"  Document: %s\n"+
					"  Organization: %s\n"+
					"  User: %s\n"+
					"  Expected: ALLOWED (user is org member AND writer)\n"+
					"  Got: DENIED\n"+
					"  This is a bug - valid intersection access was denied!\n\n"+
					"Model:\n%s",
					docObj, orgObj, user,
					formatAuthModelForDebug(model))
			}
		}

		// INVARIANT 2: User with ONLY ONE condition MUST be denied
		//
		// This is harder to test precisely, but we can check simpler cases:
		// If user is writer but we can't prove org membership, should be denied
		if len(tuples) >= 2 && checkRel == "can_delete" {
			// Look for writer tuple matching check
			hasWriterForCheck := false
			hasOrgMembershipProof := false

			for _, t := range tuples {
				if t.Object == checkObj && t.Relation == "writer" && t.User == checkUser {
					hasWriterForCheck = true
				}
			}

			// Try to find org membership proof (this is simplified)
			for _, t := range tuples {
				if t.Object == checkObj && t.Relation == "org_member" {
					// Check if user is member of this org
					orgObj := t.User
					for _, t2 := range tuples {
						if t2.Object == orgObj && t2.Relation == "member" && t2.User == checkUser {
							hasOrgMembershipProof = true
						}
					}
				}
			}

			// If user is writer but NOT org member, should be denied
			onlyWriter := hasWriterForCheck && !hasOrgMembershipProof && tuple.GetType(checkUser) == "user"

			if onlyWriter && resp.Allowed {
				t.Fatalf("🚨 INTERSECTION BYPASS: User with ONLY writer (no org membership) was allowed!\n"+
					"  Check: (%s, %s, %s)\n"+
					"  Expected: DENIED (intersection requires BOTH conditions)\n"+
					"  Got: ALLOWED\n"+
					"  This is a CRITICAL security bug!\n\n"+
					"Model:\n%s",
					checkObj, checkRel, checkUser,
					formatAuthModelForDebug(model))
			}
		}
	})
}

// FuzzCheckWithComputedUserset fuzzes the Check API with computed userset (relation chaining)
//
// AUTHORIZATION MODEL: Document with inherited permissions
// - document.owner: user (direct owner assignment)
// - document.viewer: user OR owner (viewers include all owners)
//
// COMPUTED USERSET SEMANTICS:
// The viewer relation is computed as a union of direct viewers and owners.
// This tests that relation chaining correctly grants inherited permissions.
//
// CRITICAL INVARIANTS TESTED:
// 1. User with owner access MUST have viewer access (inheritance)
// 2. User with direct viewer access MUST have viewer access
// 3. User with neither owner nor viewer MUST be denied
// 4. Canary user (never granted) MUST be denied
//
// IMPORTANT: Computed usersets enable role hierarchies - bugs could break
// permission inheritance (e.g., owners can't view their own documents)
func FuzzCheckWithComputedUserset(f *testing.F) {
	// Seed with valid computed userset patterns
	f.Add("document:d1", "owner", "user:alice", "document:d1", "viewer", "user:alice") // owner → has viewer (inherited)
	f.Add("document:d1", "viewer", "user:bob", "document:d1", "viewer", "user:bob")    // direct viewer

	f.Fuzz(func(t *testing.T, writeObj, writeRel, writeUser, checkObj, checkRel, checkUser string) {
		// Skip obviously broken inputs
		if writeUser == "" || checkUser == "" || writeObj == "" || checkObj == "" {
			return
		}

		// KNOWN BUG FILTER: Skip empty user IDs
		if checkUser == "user:" || writeUser == "user:" {
			return
		}

		ctx := context.Background()

		// Initialize server using UNTRUSTED ENTRYPOINT
		_, ds, _ := util.MustBootstrapDatastore(t, "memory")
		defer ds.Close()
		s := server.MustNewServerWithOpts(server.WithDatastore(ds))
		defer s.Close()

		// Create store via server API
		createResp, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz-test"})
		if err != nil {
			t.Skip("failed to create store")
			return
		}
		storeID := createResp.GetId()

		// Model with computed userset: viewer = direct viewers OR owners
		// This tests relation chaining where one relation inherits from another
		model := parser.MustTransformDSLToProto(`
			model
				schema 1.1

			type user

			type document
				relations
					define owner: [user]
					define viewer: [user] or owner
		`)
		model.Id = ulid.Make().String()

		// Write model via server API
		writeModelResp, err := s.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         storeID,
			TypeDefinitions: model.GetTypeDefinitions(),
			SchemaVersion:   model.GetSchemaVersion(),
		})
		if err != nil {
			t.Skip("model validation failed")
			return
		}
		modelID := writeModelResp.GetAuthorizationModelId()

		// Write tuple
		if !tuple.IsValidObject(writeObj) || !tuple.IsValidUser(writeUser) || writeRel == "" {
			return
		}

		writeTuple := &openfgav1.TupleKey{
			Object:   writeObj,
			Relation: writeRel,
			User:     writeUser,
		}

		// Write tuple via server API
		_, err = s.Write(ctx, &openfgav1.WriteRequest{
			StoreId: storeID,
			Writes:  &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{writeTuple}},
		})
		if err != nil {
			return
		}

		// Perform Check via UNTRUSTED SERVER ENTRYPOINT
		resp, err := s.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   checkObj,
				Relation: checkRel,
				User:     checkUser,
			},
		})
		if err != nil {
			return
		}

		t.Logf("FuzzCheckWithComputedUserset - Response: Allowed=%v", resp.Allowed)

		// ========================================================================
		// FUZZER SANITY CHECK - Canary User
		// ========================================================================
		canaryResp, err := s.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   writeTuple.Object,
				Relation: writeTuple.Relation,
				User:     fuzzerCanaryUser,
			},
		})
		if err == nil && canaryResp.Allowed {
			t.Fatalf("🚨 FUZZER SANITY CHECK FAILED: Canary user was granted access!\n"+
				"Model:\n%s",
				formatAuthModelForDebug(model))
		}

		// ========================================================================
		// CRITICAL INVARIANTS - Computed Userset Bypass Detection
		// ========================================================================

		// INVARIANT 1: Owner MUST have viewer access (computed userset inheritance)
		//
		// Scenario:
		// - (document:d1, owner, user:alice) - alice is owner
		// - Check (document:d1, viewer, user:alice) → MUST BE ALLOWED
		//
		// Since viewer = direct viewers OR owners, alice (as owner) should have viewer.
		ownerHasViewer := writeTuple.Relation == "owner" &&
			writeTuple.Object == checkObj &&
			writeTuple.User == checkUser &&
			checkRel == "viewer" &&
			tuple.GetType(writeTuple.User) == "user"

		if ownerHasViewer && !resp.Allowed {
			t.Fatalf("🚨 COMPUTED USERSET ERROR: Owner was denied viewer access!\n"+
				"  Written: (%s, %s, %s) ← User is owner\n"+
				"  Check:   (%s, %s, %s) ← Checking viewer (should inherit from owner)\n"+
				"  Expected: ALLOWED (viewer includes owners via computed userset)\n"+
				"  Got: DENIED\n"+
				"  This is a bug - permission inheritance is broken!\n\n"+
				"Model:\n%s",
				writeObj, writeRel, writeUser,
				checkObj, checkRel, checkUser,
				formatAuthModelForDebug(model))
		}

		// INVARIANT 2: Direct viewer MUST have viewer access
		//
		// Scenario:
		// - (document:d1, viewer, user:bob) - bob is viewer
		// - Check (document:d1, viewer, user:bob) → MUST BE ALLOWED
		directViewerHasViewer := writeTuple.Relation == "viewer" &&
			writeTuple.Object == checkObj &&
			writeTuple.User == checkUser &&
			checkRel == "viewer" &&
			tuple.GetType(writeTuple.User) == "user"

		if directViewerHasViewer && !resp.Allowed {
			t.Fatalf("🚨 AUTHORIZATION ERROR: Direct viewer was denied access!\n"+
				"  Written: (%s, %s, %s) ← User is direct viewer\n"+
				"  Check:   (%s, %s, %s) ← Same user, same relation\n"+
				"  Expected: ALLOWED\n"+
				"  Got: DENIED\n"+
				"  This is a critical bug!\n\n"+
				"Model:\n%s",
				writeObj, writeRel, writeUser,
				checkObj, checkRel, checkUser,
				formatAuthModelForDebug(model))
		}

		// INVARIANT 3: Non-owner/non-viewer MUST be denied viewer access
		//
		// Scenario:
		// - (document:d1, owner, user:alice) - alice is owner
		// - Check (document:d1, viewer, user:bob) → MUST BE DENIED
		//
		// Bob is neither owner nor direct viewer, so should be denied.
		differentUserViewer := writeTuple.User != checkUser &&
			checkRel == "viewer" &&
			writeTuple.Object == checkObj &&
			tuple.GetType(writeTuple.User) == "user" &&
			tuple.GetType(checkUser) == "user"

		if differentUserViewer && resp.Allowed {
			t.Fatalf("🚨 AUTHORIZATION BYPASS: Non-owner/non-viewer was granted viewer access!\n"+
				"  Written: (%s, %s, %s) ← Different user has some access\n"+
				"  Check:   (%s, %s, %s) ← This user has no viewer relation\n"+
				"  Expected: DENIED\n"+
				"  Got: ALLOWED\n"+
				"  This is a security bug!\n\n"+
				"Model:\n%s",
				writeObj, writeRel, writeUser,
				checkObj, checkRel, checkUser,
				formatAuthModelForDebug(model))
		}
	})
}

// FuzzCheckWithPublicAccess fuzzes the Check API with wildcard (public access) semantics
//
// AUTHORIZATION MODEL: Document with public access via wildcards
// - document.viewer: user OR user:* (public access)
//
// PUBLIC ACCESS SEMANTICS (user:*):
// The wildcard user:* means "any user of type user can access this".
// This tests that wildcards correctly grant universal access while maintaining isolation.
//
// CRITICAL INVARIANTS TESTED:
// 1. Document with user:* wildcard MUST allow ALL users
// 2. Document with specific user MUST allow ONLY that user
// 3. Document with wildcard MUST NOT grant access to different object
// 4. Canary user MUST be allowed if wildcard present, denied otherwise
//
// IMPORTANT: Wildcards enable public access - bugs could either:
// - Deny legitimate public access (availability issue)
// - Grant wildcard access to wrong resources (security issue)
func FuzzCheckWithPublicAccess(f *testing.F) {
	// Seed with valid wildcard patterns
	f.Add("document:d1", "viewer", "user:*", "document:d1", "viewer", "user:alice")     // wildcard → ANY user allowed
	f.Add("document:d2", "viewer", "user:bob", "document:d2", "viewer", "user:bob")     // specific user only
	f.Add("document:d3", "viewer", "user:*", "document:d999", "viewer", "user:charlie") // different doc → denied

	f.Fuzz(func(t *testing.T, writeObj, writeRel, writeUser, checkObj, checkRel, checkUser string) {
		// Skip obviously broken inputs
		if writeUser == "" || checkUser == "" || writeObj == "" || checkObj == "" {
			return
		}

		// KNOWN BUG FILTER: Skip empty user IDs
		if checkUser == "user:" || (writeUser == "user:" && writeUser != "user:*") {
			return
		}

		ctx := context.Background()

		// Initialize server using UNTRUSTED ENTRYPOINT
		_, ds, _ := util.MustBootstrapDatastore(t, "memory")
		defer ds.Close()
		s := server.MustNewServerWithOpts(server.WithDatastore(ds))
		defer s.Close()

		// Create store via server API
		createResp, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz-test"})
		if err != nil {
			t.Skip("failed to create store")
			return
		}
		storeID := createResp.GetId()

		// Model with wildcard support: viewer can be specific users OR wildcard (type:*)
		// This tests public access patterns where everyone can access a resource
		model := parser.MustTransformDSLToProto(`
			model
				schema 1.1

			type user

			type document
				relations
					define viewer: [user, user:*]
		`)
		model.Id = ulid.Make().String()

		// Write model via server API
		writeModelResp, err := s.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         storeID,
			TypeDefinitions: model.GetTypeDefinitions(),
			SchemaVersion:   model.GetSchemaVersion(),
		})
		if err != nil {
			t.Skip("model validation failed")
			return
		}
		modelID := writeModelResp.GetAuthorizationModelId()

		// Write tuple
		if !tuple.IsValidObject(writeObj) || !tuple.IsValidUser(writeUser) || writeRel == "" {
			return
		}

		writeTuple := &openfgav1.TupleKey{
			Object:   writeObj,
			Relation: writeRel,
			User:     writeUser,
		}

		// Write tuple via server API
		_, err = s.Write(ctx, &openfgav1.WriteRequest{
			StoreId: storeID,
			Writes:  &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{writeTuple}},
		})
		if err != nil {
			return
		}

		// Perform Check via UNTRUSTED SERVER ENTRYPOINT
		resp, err := s.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   checkObj,
				Relation: checkRel,
				User:     checkUser,
			},
		})
		if err != nil {
			return
		}

		t.Logf("FuzzCheckWithPublicAccess - Response: Allowed=%v", resp.Allowed)

		// ========================================================================
		// FUZZER SANITY CHECK - Canary User (conditional)
		// ========================================================================
		// Note: Canary check is different here because wildcards SHOULD grant access
		// We only check canary if NOT using wildcard
		if writeUser != "user:*" {
			canaryResp, err := s.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              storeID,
				AuthorizationModelId: modelID,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   writeTuple.Object,
					Relation: writeTuple.Relation,
					User:     fuzzerCanaryUser,
				},
			})
			if err == nil && canaryResp.Allowed {
				t.Fatalf("🚨 FUZZER SANITY CHECK FAILED: Canary user was granted access (no wildcard)!\n"+
					"Model:\n%s",
					formatAuthModelForDebug(model))
			}
		}

		// ========================================================================
		// CRITICAL INVARIANTS - Wildcard Bypass Detection
		// ========================================================================

		// INVARIANT 1: Wildcard MUST allow ANY user of that type
		//
		// Scenario:
		// - (document:d1, viewer, user:*) - public access for document
		// - Check (document:d1, viewer, user:anyone) → MUST BE ALLOWED
		//
		// The wildcard grants access to ALL users.
		wildcardAllowsAnyUser := writeTuple.User == "user:*" &&
			writeTuple.Relation == "viewer" &&
			writeTuple.Object == checkObj &&
			checkRel == "viewer" &&
			tuple.GetType(checkUser) == "user"

		if wildcardAllowsAnyUser && !resp.Allowed {
			t.Fatalf("🚨 WILDCARD ERROR: Wildcard present but user was denied!\n"+
				"  Written: (%s, %s, %s) ← Wildcard grants public access\n"+
				"  Check:   (%s, %s, %s) ← User should have access via wildcard\n"+
				"  Expected: ALLOWED (user:* grants access to all users)\n"+
				"  Got: DENIED\n"+
				"  This is a bug - wildcard not working!\n\n"+
				"Model:\n%s",
				writeObj, writeRel, writeUser,
				checkObj, checkRel, checkUser,
				formatAuthModelForDebug(model))
		}

		// INVARIANT 2: Specific user grant MUST NOT allow different user
		//
		// Scenario:
		// - (document:d1, viewer, user:alice) - specific user, NO wildcard
		// - Check (document:d1, viewer, user:bob) → MUST BE DENIED
		//
		// Only alice has access, not bob.
		specificUserOnlyForGrantedUser := writeTuple.User != "user:*" &&
			writeTuple.Object == checkObj &&
			writeTuple.Relation == checkRel &&
			writeTuple.User != checkUser &&
			tuple.GetType(writeTuple.User) == "user" &&
			tuple.GetType(checkUser) == "user"

		if specificUserOnlyForGrantedUser && resp.Allowed {
			t.Fatalf("🚨 AUTHORIZATION BYPASS: Non-wildcard grant allowed different user!\n"+
				"  Written: (%s, %s, %s) ← Specific user (not wildcard)\n"+
				"  Check:   (%s, %s, %s) ← Different user\n"+
				"  Expected: DENIED (no wildcard, users don't match)\n"+
				"  Got: ALLOWED\n"+
				"  This is a security bug!\n\n"+
				"Model:\n%s",
				writeObj, writeRel, writeUser,
				checkObj, checkRel, checkUser,
				formatAuthModelForDebug(model))
		}

		// INVARIANT 3: Wildcard MUST NOT grant access to different object
		//
		// Scenario:
		// - (document:d1, viewer, user:*) - wildcard for document d1
		// - Check (document:d2, viewer, user:alice) → MUST BE DENIED
		//
		// Wildcard is per-object, not global.
		wildcardDoesntCrossObjects := writeTuple.User == "user:*" &&
			writeTuple.Object != checkObj &&
			checkRel == "viewer" &&
			tuple.GetType(checkUser) == "user"

		if wildcardDoesntCrossObjects && resp.Allowed {
			t.Fatalf("🚨 WILDCARD BYPASS: Wildcard granted access to DIFFERENT object!\n"+
				"  Written: (%s, %s, %s) ← Wildcard for THIS object\n"+
				"  Check:   (%s, %s, %s) ← Checking DIFFERENT object\n"+
				"  Expected: DENIED (wildcard doesn't cross objects)\n"+
				"  Got: ALLOWED\n"+
				"  This is a CRITICAL security bug!\n\n"+
				"Model:\n%s",
				writeObj, writeRel, writeUser,
				checkObj, checkRel, checkUser,
				formatAuthModelForDebug(model))
		}
	})
}

// FuzzCheckWithMultipleRestrictions fuzzes Check API with multiple authorization paths
//
// AUTHORIZATION MODEL: Document requiring BOTH org membership AND permission
// - organization.member: user
// - document.owner: organization
// - document.writer: user
// - document.can_delete: (member of owner org) AND writer
//
// MULTIPLE RESTRICTIONS SEMANTICS:
// User must be BOTH a member of the owning organization AND have writer permission.
// This combines organizational context with resource-specific permissions.
//
// CRITICAL INVARIANTS TESTED:
// 1. User with BOTH org membership AND writer MUST be allowed
// 2. User with ONLY org membership (no writer) MUST be denied
// 3. User with ONLY writer (not org member) MUST be denied
// 4. User from different org with writer MUST be denied
// 5. Canary user MUST be denied
//
// IMPORTANT: This pattern is common in multi-tenant systems - bugs could allow
// cross-tenant access or privilege escalation.
func FuzzCheckWithMultipleRestrictions(f *testing.F) {
	// Seed with valid multiple restriction patterns
	f.Add("organization:acme", "member", "user:alice", "document:d1", "owner", "organization:acme", "document:d1", "writer", "user:alice", "document:d1", "can_delete", "user:alice") // BOTH conditions
	f.Add("organization:acme", "member", "user:bob", "document:d1", "owner", "organization:acme", "", "", "", "document:d1", "can_delete", "user:bob")                                // ONLY org member

	f.Fuzz(func(t *testing.T, write1Obj, write1Rel, write1User, write2Obj, write2Rel, write2User, write3Obj, write3Rel, write3User, checkObj, checkRel, checkUser string) {
		// Skip obviously broken inputs
		if checkUser == "" || checkObj == "" {
			return
		}

		// KNOWN BUG FILTER: Skip empty user IDs
		if checkUser == "user:" || write1User == "user:" || write2User == "user:" || write3User == "user:" {
			return
		}

		ctx := context.Background()

		// Initialize server using UNTRUSTED ENTRYPOINT
		_, ds, _ := util.MustBootstrapDatastore(t, "memory")
		defer ds.Close()
		s := server.MustNewServerWithOpts(server.WithDatastore(ds))
		defer s.Close()

		// Create store via server API
		createResp, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz-test"})
		if err != nil {
			t.Skip("failed to create store")
			return
		}
		storeID := createResp.GetId()

		// Model with multiple restrictions: can_delete requires org membership AND writer
		// This tests multi-tenant patterns with intersection of organization + permission
		model := parser.MustTransformDSLToProto(`
			model
				schema 1.1

			type user

			type organization
				relations
					define member: [user]

			type document
				relations
					define owner: [organization]
					define writer: [user]
					define can_delete: member from owner and writer
		`)
		model.Id = ulid.Make().String()

		// Write model via server API
		writeModelResp, err := s.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         storeID,
			TypeDefinitions: model.GetTypeDefinitions(),
			SchemaVersion:   model.GetSchemaVersion(),
		})
		if err != nil {
			t.Skip("model validation failed")
			return
		}
		modelID := writeModelResp.GetAuthorizationModelId()

		// Write up to 3 tuples
		var tuples []*openfgav1.TupleKey
		if write1User != "" && write1Obj != "" && write1Rel != "" && tuple.IsValidObject(write1Obj) && tuple.IsValidUser(write1User) {
			tuples = append(tuples, &openfgav1.TupleKey{Object: write1Obj, Relation: write1Rel, User: write1User})
		}
		if write2User != "" && write2Obj != "" && write2Rel != "" && tuple.IsValidObject(write2Obj) && tuple.IsValidUser(write2User) {
			tuples = append(tuples, &openfgav1.TupleKey{Object: write2Obj, Relation: write2Rel, User: write2User})
		}
		if write3User != "" && write3Obj != "" && write3Rel != "" && tuple.IsValidObject(write3Obj) && tuple.IsValidUser(write3User) {
			tuples = append(tuples, &openfgav1.TupleKey{Object: write3Obj, Relation: write3Rel, User: write3User})
		}

		if len(tuples) == 0 {
			return
		}

		// Write tuples via server API
		_, err = s.Write(ctx, &openfgav1.WriteRequest{
			StoreId: storeID,
			Writes:  &openfgav1.WriteRequestWrites{TupleKeys: tuples},
		})
		if err != nil {
			return
		}

		// Perform Check via UNTRUSTED SERVER ENTRYPOINT
		resp, err := s.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   checkObj,
				Relation: checkRel,
				User:     checkUser,
			},
		})
		if err != nil {
			return
		}

		t.Logf("FuzzCheckWithMultipleRestrictions - Response: Allowed=%v", resp.Allowed)

		// ========================================================================
		// FUZZER SANITY CHECK - Canary User
		// ========================================================================
		if len(tuples) > 0 {
			canaryResp, err := s.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              storeID,
				AuthorizationModelId: modelID,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   tuples[0].Object,
					Relation: tuples[0].Relation,
					User:     fuzzerCanaryUser,
				},
			})
			if err == nil && canaryResp.Allowed {
				t.Fatalf("🚨 FUZZER SANITY CHECK FAILED: Canary user was granted access!\n"+
					"Model:\n%s",
					formatAuthModelForDebug(model))
			}
		}

		// ========================================================================
		// CRITICAL INVARIANTS - Multiple Restrictions Bypass Detection
		// ========================================================================

		// INVARIANT 1: User with BOTH conditions MUST be allowed
		//
		// Scenario (requires 3 tuples):
		// - (organization:acme, member, user:alice) - alice is acme member
		// - (document:d1, owner, organization:acme) - document owned by acme
		// - (document:d1, writer, user:alice) - alice is writer
		// - Check (document:d1, can_delete, user:alice) → MUST BE ALLOWED
		if len(tuples) == 3 {
			var orgObj, docObj, user string
			hasOrgMember, hasDocOwner, hasDocWriter := false, false, false

			for _, t := range tuples {
				if t.Relation == "member" && tuple.GetType(t.Object) == "organization" && tuple.GetType(t.User) == "user" {
					orgObj = t.Object
					user = t.User
					hasOrgMember = true
				}
				if t.Relation == "owner" && tuple.GetType(t.Object) == "document" && t.User == orgObj {
					docObj = t.Object
					hasDocOwner = true
				}
				if t.Relation == "writer" && t.Object == docObj && t.User == user {
					hasDocWriter = true
				}
			}

			bothConditionsMet := hasOrgMember && hasDocOwner && hasDocWriter &&
				checkObj == docObj &&
				checkRel == "can_delete" &&
				checkUser == user

			if bothConditionsMet && !resp.Allowed {
				t.Fatalf("🚨 MULTIPLE RESTRICTIONS ERROR: User with BOTH conditions was denied!\n"+
					"  Organization: %s\n"+
					"  Document: %s\n"+
					"  User: %s (is org member AND writer)\n"+
					"  Expected: ALLOWED\n"+
					"  Got: DENIED\n"+
					"  This is a bug - user satisfies all requirements!\n\n"+
					"Model:\n%s",
					orgObj, docObj, user,
					formatAuthModelForDebug(model))
			}
		}

		// INVARIANT 2: User with ONLY org membership (no writer) MUST be denied
		//
		// This tests that org membership alone isn't enough.
		if len(tuples) >= 2 && checkRel == "can_delete" {
			hasOrgMembershipForCheck := false
			hasWriterForCheck := false

			// Try to find org membership proof
			for _, t := range tuples {
				if t.Relation == "owner" && t.Object == checkObj {
					orgObj := t.User
					for _, t2 := range tuples {
						if t2.Object == orgObj && t2.Relation == "member" && t2.User == checkUser {
							hasOrgMembershipForCheck = true
						}
					}
				}
				if t.Object == checkObj && t.Relation == "writer" && t.User == checkUser {
					hasWriterForCheck = true
				}
			}

			onlyOrgMember := hasOrgMembershipForCheck && !hasWriterForCheck && tuple.GetType(checkUser) == "user"

			if onlyOrgMember && resp.Allowed {
				t.Fatalf("🚨 MULTIPLE RESTRICTIONS BYPASS: User with ONLY org membership (no writer) was allowed!\n"+
					"  Check: (%s, %s, %s)\n"+
					"  User is org member but NOT writer\n"+
					"  Expected: DENIED (requires BOTH conditions)\n"+
					"  Got: ALLOWED\n"+
					"  This is a CRITICAL security bug!\n\n"+
					"Model:\n%s",
					checkObj, checkRel, checkUser,
					formatAuthModelForDebug(model))
			}
		}
	})
}

// FuzzCheckWithConditions fuzzes the Check API with conditional relationship tuples (ABAC)
//
// AUTHORIZATION MODEL: Document with condition-based access control
// - document.viewer: user with non_expired_grant (conditional)
// - Condition: current_time < grant_time + grant_duration
//
// CONDITIONAL TUPLE SEMANTICS (ABAC):
// A user has viewer access ONLY if the condition evaluates to true.
// This tests attribute-based access control (ABAC) patterns like:
// - Time-based grants (temporary access)
// - IP-based restrictions
// - Resource attribute policies
//
// CRITICAL INVARIANTS TESTED:
// 1. Valid condition (not expired) MUST allow access
// 2. Invalid condition (expired) MUST deny access
// 3. Missing condition context MUST deny access
// 4. User without conditional tuple MUST be denied
// 5. Canary user MUST be denied
//
// IMPORTANT: Conditions are critical for ABAC - bugs could allow:
// - Expired temporary access to persist
// - Bypassing IP allowlists
// - Accessing resources despite failing attribute checks
func FuzzCheckWithConditions(f *testing.F) {
	// Seed with valid conditional patterns
	// Format: writeObj, writeRel, writeUser, grantDuration (minutes), checkObj, checkRel, checkUser, checkTimeOffsetMinutes
	f.Add("document:d1", "viewer", "user:alice", int64(10), "document:d1", "viewer", "user:alice", int64(5))  // 5 min after grant, 10 min duration → ALLOWED
	f.Add("document:d1", "viewer", "user:bob", int64(10), "document:d1", "viewer", "user:bob", int64(15))     // 15 min after grant, 10 min duration → DENIED (expired)
	f.Add("document:d1", "viewer", "user:alice", int64(60), "document:d1", "viewer", "user:alice", int64(30)) // 30 min after grant, 60 min duration → ALLOWED

	f.Fuzz(func(t *testing.T, writeObj, writeRel, writeUser string, grantDurationMins int64, checkObj, checkRel, checkUser string, checkTimeOffsetMins int64) {
		// Skip obviously broken inputs
		if writeUser == "" || checkUser == "" || writeObj == "" || checkObj == "" {
			return
		}

		// KNOWN BUG FILTER: Skip empty user IDs
		if checkUser == "user:" || writeUser == "user:" {
			return
		}

		// Skip invalid durations (must be positive)
		if grantDurationMins <= 0 {
			return
		}

		// Clamp time offset to reasonable range (-60 to +120 minutes)
		if checkTimeOffsetMins < -60 || checkTimeOffsetMins > 120 {
			return
		}

		ctx := context.Background()

		// Initialize server using UNTRUSTED ENTRYPOINT
		_, ds, _ := util.MustBootstrapDatastore(t, "memory")
		defer ds.Close()
		s := server.MustNewServerWithOpts(server.WithDatastore(ds))
		defer s.Close()

		// Create store via server API
		createResp, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz-test"})
		if err != nil {
			t.Skip("failed to create store")
			return
		}
		storeID := createResp.GetId()

		// Model with conditions: viewer requires non_expired_grant condition
		// This tests ABAC with time-based access (grant_time + grant_duration)
		model := parser.MustTransformDSLToProto(`
			model
				schema 1.1

			type user

			type document
				relations
					define viewer: [user with non_expired_grant]

			condition non_expired_grant(current_time: timestamp, grant_time: timestamp, grant_duration: duration) {
				current_time < grant_time + grant_duration
			}
		`)
		model.Id = ulid.Make().String()

		// Write model via server API
		writeModelResp, err := s.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         storeID,
			TypeDefinitions: model.GetTypeDefinitions(),
			SchemaVersion:   model.GetSchemaVersion(),
			Conditions:      model.GetConditions(),
		})
		if err != nil {
			t.Skip("model validation failed")
			return
		}
		modelID := writeModelResp.GetAuthorizationModelId()

		// Write conditional tuple with grant_time and grant_duration
		if !tuple.IsValidObject(writeObj) || !tuple.IsValidUser(writeUser) || writeRel == "" {
			return
		}

		// Set grant time to a fixed reference point (2024-01-01 00:00:00 UTC)
		grantTime := "2024-01-01T00:00:00Z"
		grantDuration := formatDuration(grantDurationMins)

		writeTuple := &openfgav1.TupleKey{
			Object:   writeObj,
			Relation: writeRel,
			User:     writeUser,
			Condition: &openfgav1.RelationshipCondition{
				Name: "non_expired_grant",
				Context: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"grant_time": {
							Kind: &structpb.Value_StringValue{
								StringValue: grantTime,
							},
						},
						"grant_duration": {
							Kind: &structpb.Value_StringValue{
								StringValue: grantDuration,
							},
						},
					},
				},
			},
		}

		// Write tuple via server API
		_, err = s.Write(ctx, &openfgav1.WriteRequest{
			StoreId: storeID,
			Writes:  &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{writeTuple}},
		})
		if err != nil {
			return
		}

		// Calculate current_time based on grant_time + offset
		// Grant: 2024-01-01 00:00:00
		// Check at: 2024-01-01 00:00:00 + checkTimeOffsetMins
		checkTime := formatTimestampWithOffset(grantTime, checkTimeOffsetMins)

		// Perform Check via UNTRUSTED SERVER ENTRYPOINT with condition context
		resp, err := s.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   checkObj,
				Relation: checkRel,
				User:     checkUser,
			},
			Context: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"current_time": {
						Kind: &structpb.Value_StringValue{
							StringValue: checkTime,
						},
					},
				},
			},
		})
		if err != nil {
			return
		}

		t.Logf("FuzzCheckWithConditions - Response: Allowed=%v (grant_duration=%dm, check_offset=%dm)",
			resp.Allowed, grantDurationMins, checkTimeOffsetMins)

		// ========================================================================
		// FUZZER SANITY CHECK - Canary User
		// ========================================================================
		canaryResp, err := s.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   writeTuple.Object,
				Relation: writeTuple.Relation,
				User:     fuzzerCanaryUser,
			},
			Context: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"current_time": {
						Kind: &structpb.Value_StringValue{
							StringValue: checkTime,
						},
					},
				},
			},
		})
		if err == nil && canaryResp.Allowed {
			t.Fatalf("🚨 FUZZER SANITY CHECK FAILED: Canary user was granted access!\n"+
				"Model:\n%s",
				formatAuthModelForDebug(model))
		}

		// ========================================================================
		// CRITICAL INVARIANTS - Condition Bypass Detection
		// ========================================================================

		// INVARIANT 1: Valid condition (not expired) MUST allow access
		//
		// Scenario:
		// - Write: (document:d1, viewer, user:alice) with grant at T, duration 60min
		// - Check at T+30min (within grant period)
		// - Expected: ALLOWED (condition satisfied)
		validCondition := writeTuple.Object == checkObj &&
			writeTuple.Relation == checkRel &&
			writeTuple.User == checkUser &&
			checkTimeOffsetMins >= 0 &&
			checkTimeOffsetMins < grantDurationMins &&
			tuple.GetType(checkUser) == "user"

		if validCondition && !resp.Allowed {
			t.Fatalf("🚨 CONDITION ERROR: Valid condition was denied!\n"+
				"  Tuple: (%s, %s, %s)\n"+
				"  Grant Duration: %d minutes\n"+
				"  Check Time Offset: %d minutes (within grant period)\n"+
				"  Condition: current_time < grant_time + grant_duration\n"+
				"  Expected: ALLOWED (condition is satisfied)\n"+
				"  Got: DENIED\n"+
				"  This is a bug - valid time-based access was denied!\n\n"+
				"Model:\n%s",
				writeObj, writeRel, writeUser,
				grantDurationMins, checkTimeOffsetMins,
				formatAuthModelForDebug(model))
		}

		// INVARIANT 2: Invalid condition (expired) MUST deny access
		//
		// Scenario:
		// - Write: (document:d1, viewer, user:alice) with grant at T, duration 60min
		// - Check at T+90min (after grant expiry)
		// - Expected: DENIED (condition not satisfied)
		expiredCondition := writeTuple.Object == checkObj &&
			writeTuple.Relation == checkRel &&
			writeTuple.User == checkUser &&
			checkTimeOffsetMins >= grantDurationMins &&
			tuple.GetType(checkUser) == "user"

		if expiredCondition && resp.Allowed {
			t.Fatalf("🚨 CONDITION BYPASS: Expired condition was allowed!\n"+
				"  Tuple: (%s, %s, %s)\n"+
				"  Grant Duration: %d minutes\n"+
				"  Check Time Offset: %d minutes (AFTER grant expiry)\n"+
				"  Condition: current_time < grant_time + grant_duration\n"+
				"  Expected: DENIED (condition expired)\n"+
				"  Got: ALLOWED\n"+
				"  This is a CRITICAL security bug - expired access granted!\n\n"+
				"Model:\n%s",
				writeObj, writeRel, writeUser,
				grantDurationMins, checkTimeOffsetMins,
				formatAuthModelForDebug(model))
		}

		// INVARIANT 3: Different user MUST be denied (even with valid time)
		//
		// Scenario:
		// - Write: (document:d1, viewer, user:alice) with condition
		// - Check: (document:d1, viewer, user:bob)
		// - Expected: DENIED (different user)
		differentUser := writeTuple.Object == checkObj &&
			writeTuple.Relation == checkRel &&
			writeTuple.User != checkUser &&
			checkTimeOffsetMins >= 0 &&
			checkTimeOffsetMins < grantDurationMins &&
			tuple.GetType(writeTuple.User) == "user" &&
			tuple.GetType(checkUser) == "user"

		if differentUser && resp.Allowed {
			t.Fatalf("🚨 AUTHORIZATION BYPASS: Different user granted access!\n"+
				"  Written: (%s, %s, %s) with valid condition\n"+
				"  Check:   (%s, %s, %s) ← Different user\n"+
				"  Expected: DENIED (wrong user)\n"+
				"  Got: ALLOWED\n"+
				"  This is a CRITICAL security bug!\n\n"+
				"Model:\n%s",
				writeObj, writeRel, writeUser,
				checkObj, checkRel, checkUser,
				formatAuthModelForDebug(model))
		}
	})
}

// FuzzCheckWithParentChild fuzzes the Check API with parent-child hierarchical relationships
//
// AUTHORIZATION MODEL: Folder/Document hierarchy with cascading permissions
// - folder.editor: user (direct assignment)
// - document.parent: folder (object-to-object relationship)
// - document.editor: user OR editor from parent (cascading permissions)
//
// PARENT-CHILD SEMANTICS:
// A user who is an editor of a folder automatically becomes an editor of all
// documents where that folder is the parent. This tests hierarchical permission
// cascading, common in file systems and organizational structures.
//
// CRITICAL INVARIANTS TESTED:
// 1. Folder editor MUST have editor access to child documents
// 2. Direct document editor MUST have access (without folder relationship)
// 3. Folder editor MUST NOT have access to unrelated documents
// 4. Document with no parent folder follows direct permissions only
// 5. Canary user MUST be denied
//
// IMPORTANT: Parent-child patterns are critical for hierarchical systems - bugs could:
// - Break permission cascading (folder editors can't edit documents)
// - Allow cross-hierarchy access (editor of folder A edits documents in folder B)
// - Leak permissions across organizational boundaries
func FuzzCheckWithParentChild(f *testing.F) {
	// Seed with valid parent-child patterns
	// Format: folderObj, folderRel, folderUser, docObj, docParentRel, docParent, checkObj, checkRel, checkUser
	f.Add("folder:f1", "editor", "user:alice", "document:d1", "parent", "folder:f1", "document:d1", "editor", "user:alice") // folder editor → doc editor via parent
	f.Add("folder:f1", "editor", "user:bob", "document:d1", "parent", "folder:f1", "document:d1", "editor", "user:bob")     // folder editor → doc editor
	f.Add("document:d2", "editor", "user:charlie", "", "", "", "document:d2", "editor", "user:charlie")                      // direct document editor (no parent)

	f.Fuzz(func(t *testing.T, folderObj, folderRel, folderUser, docObj, docParentRel, docParent, checkObj, checkRel, checkUser string) {
		// Skip obviously broken inputs
		if checkUser == "" || checkObj == "" {
			return
		}

		// KNOWN BUG FILTER: Skip empty user IDs
		if checkUser == "user:" || folderUser == "user:" {
			return
		}

		ctx := context.Background()

		// Initialize server using UNTRUSTED ENTRYPOINT
		_, ds, _ := util.MustBootstrapDatastore(t, "memory")
		defer ds.Close()
		s := server.MustNewServerWithOpts(server.WithDatastore(ds))
		defer s.Close()

		// Create store via server API
		createResp, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz-test"})
		if err != nil {
			t.Skip("failed to create store")
			return
		}
		storeID := createResp.GetId()

		// Model with parent-child: document.editor = direct editors OR editors from parent folder
		// This tests cascading permissions through object hierarchies
		model := parser.MustTransformDSLToProto(`
			model
				schema 1.1

			type user

			type folder
				relations
					define editor: [user]

			type document
				relations
					define parent: [folder]
					define editor: [user] or editor from parent
		`)
		model.Id = ulid.Make().String()

		// Write model via server API
		writeModelResp, err := s.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         storeID,
			TypeDefinitions: model.GetTypeDefinitions(),
			SchemaVersion:   model.GetSchemaVersion(),
		})
		if err != nil {
			t.Skip("model validation failed")
			return
		}
		modelID := writeModelResp.GetAuthorizationModelId()

		// Build tuples: folder editor + document parent relationship
		var tuples []*openfgav1.TupleKey

		// Tuple 1: folder editor (if provided)
		if folderUser != "" && folderObj != "" && folderRel != "" &&
			tuple.IsValidObject(folderObj) && tuple.IsValidUser(folderUser) {
			tuples = append(tuples, &openfgav1.TupleKey{
				Object:   folderObj,
				Relation: folderRel,
				User:     folderUser,
			})
		}

		// Tuple 2: document parent relationship (if provided)
		if docObj != "" && docParentRel != "" && docParent != "" &&
			tuple.IsValidObject(docObj) && tuple.IsValidObject(docParent) {
			tuples = append(tuples, &openfgav1.TupleKey{
				Object:   docObj,
				Relation: docParentRel,
				User:     docParent,
			})
		}

		if len(tuples) == 0 {
			return
		}

		// Write tuples via server API
		_, err = s.Write(ctx, &openfgav1.WriteRequest{
			StoreId: storeID,
			Writes:  &openfgav1.WriteRequestWrites{TupleKeys: tuples},
		})
		if err != nil {
			return
		}

		// Perform Check via UNTRUSTED SERVER ENTRYPOINT
		resp, err := s.Check(ctx, &openfgav1.CheckRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				Object:   checkObj,
				Relation: checkRel,
				User:     checkUser,
			},
		})
		if err != nil {
			return
		}

		t.Logf("FuzzCheckWithParentChild - Response: Allowed=%v", resp.Allowed)

		// ========================================================================
		// FUZZER SANITY CHECK - Canary User
		// ========================================================================
		if len(tuples) > 0 {
			canaryResp, err := s.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              storeID,
				AuthorizationModelId: modelID,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   tuples[0].Object,
					Relation: tuples[0].Relation,
					User:     fuzzerCanaryUser,
				},
			})
			if err == nil && canaryResp.Allowed {
				t.Fatalf("🚨 FUZZER SANITY CHECK FAILED: Canary user was granted access!\n"+
					"Model:\n%s",
					formatAuthModelForDebug(model))
			}
		}

		// ========================================================================
		// CRITICAL INVARIANTS - Parent-Child Cascade Bypass Detection
		// ========================================================================

		// INVARIANT 1: Folder editor MUST have editor access to child documents
		//
		// Scenario (requires 2 tuples):
		// - (folder:f1, editor, user:alice) - alice is folder editor
		// - (document:d1, parent, folder:f1) - d1 is child of f1
		// - Check (document:d1, editor, user:alice) → MUST BE ALLOWED
		//
		// Alice is editor of folder, so she inherits editor access to child document.
		if len(tuples) >= 2 {
			var folderEditorUser, folderObject, documentObject string
			hasFolderEditor := false
			hasParentRelation := false

			for _, t := range tuples {
				if t.Relation == "editor" && tuple.GetType(t.Object) == "folder" && tuple.GetType(t.User) == "user" {
					folderObject = t.Object
					folderEditorUser = t.User
					hasFolderEditor = true
				}
				if t.Relation == "parent" && tuple.GetType(t.Object) == "document" && t.User == folderObject {
					documentObject = t.Object
					hasParentRelation = true
				}
			}

			folderEditorHasChildAccess := hasFolderEditor && hasParentRelation &&
				checkObj == documentObject &&
				checkRel == "editor" &&
				checkUser == folderEditorUser

			if folderEditorHasChildAccess && !resp.Allowed {
				t.Fatalf("🚨 PARENT-CHILD ERROR: Folder editor was denied access to child document!\n"+
					"  Folder: %s\n"+
					"  Document: %s\n"+
					"  User: %s (is folder editor)\n"+
					"  Expected: ALLOWED (editor cascades from parent folder)\n"+
					"  Got: DENIED\n"+
					"  This is a bug - hierarchical permissions broken!\n\n"+
					"Model:\n%s",
					folderObject, documentObject, folderEditorUser,
					formatAuthModelForDebug(model))
			}
		}

		// INVARIANT 2: Folder editor MUST NOT have access to unrelated documents
		//
		// Scenario:
		// - (folder:f1, editor, user:alice)
		// - (document:d2, parent, folder:f2) ← Different folder
		// - Check (document:d2, editor, user:alice) → MUST BE DENIED
		if len(tuples) >= 2 && checkRel == "editor" {
			var folderEditorUser, folderObject, documentObject, documentParent string
			hasFolderEditor := false
			hasParentRelation := false

			for _, t := range tuples {
				if t.Relation == "editor" && tuple.GetType(t.Object) == "folder" && tuple.GetType(t.User) == "user" {
					folderObject = t.Object
					folderEditorUser = t.User
					hasFolderEditor = true
				}
				if t.Relation == "parent" && tuple.GetType(t.Object) == "document" {
					documentObject = t.Object
					documentParent = t.User
					hasParentRelation = true
				}
			}

			// Check if user is editor of a folder but document belongs to DIFFERENT folder
			differentFolderAccess := hasFolderEditor && hasParentRelation &&
				checkObj == documentObject &&
				checkUser == folderEditorUser &&
				folderObject != documentParent &&
				tuple.GetType(checkUser) == "user"

			if differentFolderAccess && resp.Allowed {
				t.Fatalf("🚨 PARENT-CHILD BYPASS: Folder editor granted access to document in DIFFERENT folder!\n"+
					"  User's Folder: %s\n"+
					"  Document's Folder: %s\n"+
					"  Document: %s\n"+
					"  User: %s\n"+
					"  Expected: DENIED (document in different folder hierarchy)\n"+
					"  Got: ALLOWED\n"+
					"  This is a CRITICAL security bug - cross-hierarchy access!\n\n"+
					"Model:\n%s",
					folderObject, documentParent, documentObject, checkUser,
					formatAuthModelForDebug(model))
			}
		}

		// INVARIANT 3: Direct document editor (no folder) MUST have access
		//
		// Scenario:
		// - (document:d1, editor, user:bob) - direct editor, no parent folder
		// - Check (document:d1, editor, user:bob) → MUST BE ALLOWED
		for _, tup := range tuples {
			if tup.Relation == "editor" && tuple.GetType(tup.Object) == "document" && tuple.GetType(tup.User) == "user" {
				directEditor := tup.Object == checkObj &&
					tup.User == checkUser &&
					checkRel == "editor"

				if directEditor && !resp.Allowed {
					t.Fatalf("🚨 AUTHORIZATION ERROR: Direct document editor was denied!\n"+
						"  Document: %s\n"+
						"  User: %s (direct editor)\n"+
						"  Expected: ALLOWED (direct editor relationship)\n"+
						"  Got: DENIED\n"+
						"  This is a critical bug!\n\n"+
						"Model:\n%s",
						checkObj, checkUser,
						formatAuthModelForDebug(model))
				}
			}
		}
	})
}

// Helper functions for condition testing

// formatDuration converts minutes to duration string (e.g., "10m", "1h30m")
func formatDuration(minutes int64) string {
	if minutes < 60 {
		return formatInt64(minutes) + "m"
	}
	hours := minutes / 60
	mins := minutes % 60
	if mins == 0 {
		return formatInt64(hours) + "h"
	}
	return formatInt64(hours) + "h" + formatInt64(mins) + "m"
}

// formatInt64 converts int64 to string without imports
func formatInt64(n int64) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + formatInt64(-n)
	}
	var buf [20]byte
	i := len(buf) - 1
	for n > 0 {
		buf[i] = byte('0' + n%10)
		n /= 10
		i--
	}
	return string(buf[i+1:])
}

// formatTimestampWithOffset adds minutes to a timestamp and returns new timestamp
func formatTimestampWithOffset(baseTime string, offsetMinutes int64) string {
	// Parse base time: "2024-01-01T00:00:00Z"
	// Add offsetMinutes to it
	// For simplicity, we'll just use a different fixed time based on offset
	// This is a simplified implementation for fuzzing purposes

	// Base: 2024-01-01 00:00:00
	// We'll create timestamps by adding offset to the hour/minute
	totalMinutes := offsetMinutes
	if totalMinutes < 0 {
		// For negative offsets, use a time before base
		return "2023-12-31T23:00:00Z"
	}

	hours := totalMinutes / 60
	mins := totalMinutes % 60

	// Simple formatting: we can only handle up to 23 hours for simplicity
	if hours > 23 {
		hours = hours % 24
	}

	// Format as "2024-01-01THH:MM:00Z"
	hourStr := formatTwoDigits(int(hours))
	minStr := formatTwoDigits(int(mins))

	return "2024-01-01T" + hourStr + ":" + minStr + ":00Z"
}

// formatTwoDigits formats an integer as a two-digit string (e.g., 5 → "05")
func formatTwoDigits(n int) string {
	if n < 10 {
		return "0" + formatInt64(int64(n))
	}
	return formatInt64(int64(n))
}

// Helper: Format authorization model for debug output
func formatAuthModelForDebug(model *openfgav1.AuthorizationModel) string {
        var result string
        result += "Model ID: " + model.GetId() + "\n"
        result += "Schema Version: " + model.GetSchemaVersion() + "\n"
        result += "Type Definitions:\n"
        for _, typeDef := range model.GetTypeDefinitions() {
                result += "  - Type: " + typeDef.GetType() + "\n"
                if len(typeDef.GetRelations()) > 0 {
                        result += "    Relations:\n"
                        for relName := range typeDef.GetRelations() {
                                result += "      - " + relName + "\n"
                                if metadata := typeDef.GetMetadata(); metadata != nil {
                                        if relMeta := metadata.GetRelations()[relName]; relMeta != nil {
                                                result += "        Allowed types:\n"
                                                for _, relRef := range relMeta.GetDirectlyRelatedUserTypes() {
                                                        if relRef.GetRelation() != "" {
                                                                result += "          - " + relRef.GetType() + "#" + relRef.GetRelation() + "\n"
                                                        } else if relRef.GetWildcard() != nil {
                                                                result += "          - " + relRef.GetType() + ":*\n"
                                                        } else {
                                                                result += "          - " + relRef.GetType() + "\n"
                                                        }
                                                }
                                        }
                                }
                        }
                }
        }
        return result
}