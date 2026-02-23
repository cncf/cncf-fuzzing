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
	"github.com/openfga/openfga/pkg/typesystem"
)

// FuzzRecursivePublicAccessConsistency tests GHSA-jq9f-gm9w-rwm9 (CVE-2026-24851)
// CVE: Check calls return incorrect results when a relation is assignable by both
// user:* (public) AND userset references (TYPE#relation), especially through
// recursive chains. The bug is ordering-dependent: lexicographic ordering of
// object names affects whether the recursive resolver correctly propagates
// public access through chains.
//
// Vulnerability pattern:
// 1. Model: define access: [user, user:*, node#access] (recursive + public + direct)
// 2. Build a chain: node:A#access@node:B#access, node:B#access@user:*
// 3. Check node:A#access@user:charlie → should be ALLOWED (reachable via chain to public root)
// 4. BUG: Returns denied depending on lexicographic ordering of object names
//
// This fuzzer builds a graph of 5 objects with mixed tuple types and verifies
// that Check results match a computed reachability oracle.
func FuzzRecursivePublicAccessConsistency(f *testing.F) {
	f.Fuzz(func(t *testing.T, modelChoice uint8,
		obj0Cfg, obj1Cfg, obj2Cfg, obj3Cfg, obj4Cfg uint8,
		extraUser1, extraUser2 string) {

		if extraUser1 == "" || extraUser2 == "" {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		datastore := memory.New()
		// Use a low resolve node limit (5) so that long recursive chains
		// trigger the maxResolutionDepth path in breadthFirstRecursiveMatch
		srv := newRecursiveFuzzServer(datastore)
		defer func() {
			srv.Close()
			datastore.Close()
		}()

		store, err := srv.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "fuzz"})
		if err != nil {
			return
		}

		// Select model based on modelChoice
		numModels := uint8(4)
		var dsl *openfgav1.AuthorizationModel
		switch modelChoice % numModels {
		case 0:
			// Basic recursive with public
			dsl = parser.MustTransformDSLToProto(`
				model
				  schema 1.1
				type user
				type node
				  relations
				    define access: [user, user:*, node#access]
			`)
		case 1:
			// Recursive with union (editor relation)
			dsl = parser.MustTransformDSLToProto(`
				model
				  schema 1.1
				type user
				type node
				  relations
				    define editor: [user]
				    define access: [user, user:*, node#access] or editor
			`)
		case 2:
			// Public-only recursive (no direct user assignment except via wildcard)
			dsl = parser.MustTransformDSLToProto(`
				model
				  schema 1.1
				type user
				type node
				  relations
				    define access: [user:*, node#access]
			`)
		case 3:
			// Recursive TTU: access is resolved via parent relation (tuple-to-userset)
			// This exercises recursiveTTU and the TTUKind branch in buildRecursiveMapper
			dsl = parser.MustTransformDSLToProto(`
				model
				  schema 1.1
				type user
				type node
				  relations
				    define parent: [node]
				    define access: [user, user:*] or access from parent
			`)
		}

		model, err := srv.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         store.Id,
			TypeDefinitions: dsl.GetTypeDefinitions(),
			SchemaVersion:   typesystem.SchemaVersion1_1,
		})
		if err != nil {
			return
		}
		modelID := model.AuthorizationModelId

		// Generate object names based on config bits 4-5 (lexicographic ordering variants)
		objConfigs := []uint8{obj0Cfg, obj1Cfg, obj2Cfg, obj3Cfg, obj4Cfg}
		objNames := make([]string, 5)
		for i, cfg := range objConfigs {
			switch (cfg >> 4) & 3 {
			case 0:
				objNames[i] = fmt.Sprintf("node:obj_a_%d", i) // ascending
			case 1:
				objNames[i] = fmt.Sprintf("node:obj_z_%d", i) // descending prefix
			case 2:
				objNames[i] = fmt.Sprintf("node:obj_%d0_%d", i+1, i) // numeric trick
			case 3:
				objNames[i] = fmt.Sprintf("node:obj_m_%d", i) // neutral
			}
		}

		// Track which objects have public access and graph edges
		hasPublic := make([]bool, 5)
		hasDirectUser := make([]bool, 5)
		// adjacency: edges[i] contains indices j such that obj[i] has a chain to obj[j]#access
		edges := make([][]int, 5)
		for i := range edges {
			edges[i] = []int{}
		}

		isTTUModel := modelChoice%numModels == 3

		// Write tuples based on config bits 0-3
		for i, cfg := range objConfigs {
			// bit 0: direct user assignment
			if cfg&1 != 0 && modelChoice%numModels != 2 { // model 2 doesn't allow direct user
				directUser := fmt.Sprintf("user:granted_%d", i)
				_, err := srv.Write(ctx, &openfgav1.WriteRequest{
					StoreId:              store.Id,
					AuthorizationModelId: modelID,
					Writes: &openfgav1.WriteRequestWrites{
						TupleKeys: []*openfgav1.TupleKey{{
							Object:   objNames[i],
							Relation: "access",
							User:     directUser,
						}},
					},
				})
				if err == nil {
					hasDirectUser[i] = true
				}
			}

			// bit 1: wildcard (user:*)
			if cfg&2 != 0 {
				_, err := srv.Write(ctx, &openfgav1.WriteRequest{
					StoreId:              store.Id,
					AuthorizationModelId: modelID,
					Writes: &openfgav1.WriteRequestWrites{
						TupleKeys: []*openfgav1.TupleKey{{
							Object:   objNames[i],
							Relation: "access",
							User:     "user:*",
						}},
					},
				})
				if err == nil {
					hasPublic[i] = true
				}
			}

			// bit 2: chain to next object (i → i+1)
			if cfg&4 != 0 && i < 4 {
				nextObj := objNames[i+1]
				if isTTUModel {
					// For TTU model, create parent relation instead of userset reference
					_, err := srv.Write(ctx, &openfgav1.WriteRequest{
						StoreId:              store.Id,
						AuthorizationModelId: modelID,
						Writes: &openfgav1.WriteRequestWrites{
							TupleKeys: []*openfgav1.TupleKey{{
								Object:   objNames[i],
								Relation: "parent",
								User:     nextObj,
							}},
						},
					})
					if err == nil {
						edges[i] = append(edges[i], i+1)
					}
				} else {
					_, err := srv.Write(ctx, &openfgav1.WriteRequest{
						StoreId:              store.Id,
						AuthorizationModelId: modelID,
						Writes: &openfgav1.WriteRequestWrites{
							TupleKeys: []*openfgav1.TupleKey{{
								Object:   objNames[i],
								Relation: "access",
								User:     nextObj + "#access",
							}},
						},
					})
					if err == nil {
						edges[i] = append(edges[i], i+1)
					}
				}
			}

			// bit 3: skip-chain to object (i → i+2)
			if cfg&8 != 0 && i < 3 {
				skipObj := objNames[i+2]
				if isTTUModel {
					// For TTU model, create parent relation instead of userset reference
					_, err := srv.Write(ctx, &openfgav1.WriteRequest{
						StoreId:              store.Id,
						AuthorizationModelId: modelID,
						Writes: &openfgav1.WriteRequestWrites{
							TupleKeys: []*openfgav1.TupleKey{{
								Object:   objNames[i],
								Relation: "parent",
								User:     skipObj,
							}},
						},
					})
					if err == nil {
						edges[i] = append(edges[i], i+2)
					}
				} else {
					_, err := srv.Write(ctx, &openfgav1.WriteRequest{
						StoreId:              store.Id,
						AuthorizationModelId: modelID,
						Writes: &openfgav1.WriteRequestWrites{
							TupleKeys: []*openfgav1.TupleKey{{
								Object:   objNames[i],
								Relation: "access",
								User:     skipObj + "#access",
							}},
						},
					})
					if err == nil {
						edges[i] = append(edges[i], i+2)
					}
				}
			}
		}

		// Compute reachability oracle: which objects are publicly accessible?
		// An object is publicly accessible if:
		// 1. It has user:* directly, OR
		// 2. It has a chain edge to an object that is publicly accessible (recursive)
		publiclyAccessible := computePublicReachability(hasPublic, edges)

		// Verify invariants
		for i := 0; i < 5; i++ {
			// Test with extraUser1
			checkUser1 := fmt.Sprintf("user:%s", extraUser1)
			resp1, err := srv.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              store.Id,
				AuthorizationModelId: modelID,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   objNames[i],
					Relation: "access",
					User:     checkUser1,
				},
			})
			if err != nil {
				continue
			}

			// Test with extraUser2
			checkUser2 := fmt.Sprintf("user:%s", extraUser2)
			resp2, err := srv.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              store.Id,
				AuthorizationModelId: modelID,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   objNames[i],
					Relation: "access",
					User:     checkUser2,
				},
			})
			if err != nil {
				continue
			}

			if publiclyAccessible[i] {
				// Publicly accessible objects should allow ANY user
				// (unless the user happens to be a granted_N user, which is also fine)
				isUser1Granted := false
				isUser2Granted := false
				for j := 0; j < 5; j++ {
					if hasDirectUser[j] && objNames[j] == objNames[i] {
						if checkUser1 == fmt.Sprintf("user:granted_%d", j) {
							isUser1Granted = true
						}
						if checkUser2 == fmt.Sprintf("user:granted_%d", j) {
							isUser2Granted = true
						}
					}
				}
				_ = isUser1Granted
				_ = isUser2Granted

				if !resp1.Allowed {
					t.Fatalf("VULNERABILITY: CVE-2026-24851 recursive public access inconsistency!\n"+
						"Object %s is publicly accessible (reachable from user:* via chain)\n"+
						"But Check with %s returned DENIED\n"+
						"Model choice: %d\n"+
						"Public objects: %v\n"+
						"Edges: %v\n"+
						"Reachability: %v\n"+
						"Object names: %v",
						objNames[i], checkUser1, modelChoice%numModels,
						hasPublic, edges, publiclyAccessible, objNames)
				}
				if !resp2.Allowed {
					t.Fatalf("VULNERABILITY: CVE-2026-24851 recursive public access inconsistency!\n"+
						"Object %s is publicly accessible (reachable from user:* via chain)\n"+
						"But Check with %s returned DENIED\n"+
						"Model choice: %d\n"+
						"Public objects: %v\n"+
						"Edges: %v\n"+
						"Reachability: %v\n"+
						"Object names: %v",
						objNames[i], checkUser2, modelChoice%numModels,
						hasPublic, edges, publiclyAccessible, objNames)
				}
			}

			// Consistency check: same query twice must return same result
			resp1Again, err := srv.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              store.Id,
				AuthorizationModelId: modelID,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   objNames[i],
					Relation: "access",
					User:     checkUser1,
				},
			})
			if err != nil {
				continue
			}
			if resp1.Allowed != resp1Again.Allowed {
				t.Fatalf("INCONSISTENCY: Same Check query returned different results!\n"+
					"Object: %s, User: %s\n"+
					"First call: %v, Second call: %v\n"+
					"Model choice: %d\n"+
					"Object names: %v",
					objNames[i], checkUser1, resp1.Allowed, resp1Again.Allowed,
					modelChoice%numModels, objNames)
			}
		}

		// Canary check: user that was never granted anything should not have access
		// to objects that are NOT publicly accessible and don't have direct grants
		for i := 0; i < 5; i++ {
			if publiclyAccessible[i] || hasDirectUser[i] {
				continue
			}
			canaryResp, err := srv.Check(ctx, &openfgav1.CheckRequest{
				StoreId:              store.Id,
				AuthorizationModelId: modelID,
				TupleKey: &openfgav1.CheckRequestTupleKey{
					Object:   objNames[i],
					Relation: "access",
					User:     fuzzerCanaryUser,
				},
			})
			if err != nil {
				continue
			}
			if canaryResp.Allowed {
				t.Fatalf("VULNERABILITY: Canary user granted access to non-public object!\n"+
					"Object %s has no public access and no direct grant\n"+
					"But canary user was granted access\n"+
					"Model choice: %d\n"+
					"Public objects: %v\n"+
					"Direct users: %v\n"+
					"Edges: %v\n"+
					"Reachability: %v\n"+
					"Object names: %v",
					objNames[i], modelChoice%numModels,
					hasPublic, hasDirectUser, edges, publiclyAccessible, objNames)
			}
		}
	})
}

// computePublicReachability determines which objects are publicly accessible.
// An object is publicly accessible if it has user:* OR has a chain edge to
// a publicly accessible object (transitive closure).
func computePublicReachability(hasPublic []bool, edges [][]int) []bool {
	n := len(hasPublic)
	reachable := make([]bool, n)
	copy(reachable, hasPublic)

	// Fixed-point iteration: propagate reachability through edges
	// edges[i] contains j means obj[i] has access via obj[j]#access
	// So if obj[j] is publicly accessible, obj[i] is too
	changed := true
	for changed {
		changed = false
		for i := 0; i < n; i++ {
			if reachable[i] {
				continue
			}
			for _, j := range edges[i] {
				if reachable[j] {
					reachable[i] = true
					changed = true
					break
				}
			}
		}
	}
	return reachable
}
