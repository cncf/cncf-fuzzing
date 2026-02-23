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
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	parser "github.com/openfga/language/pkg/go/transformer"

	"github.com/openfga/openfga/cmd/util"
	"github.com/openfga/openfga/internal/authz"
	"github.com/openfga/openfga/internal/utils/apimethod"
	"github.com/openfga/openfga/pkg/authclaims"
	"github.com/openfga/openfga/pkg/logger"
)

// authzModelDSL is the authorization model that OpenFGA uses for its own access control.
const authzModelDSL = `
model
  schema 1.1

type system
  relations
    define can_call_create_stores: [application, application:*] or admin
    define can_call_list_stores: [application, application:*] or admin
    define admin: [application]

type application

type module
  relations
    define can_call_write: [application] or writer or writer from store
    define store: [store]
    define writer: [application]

type store
  relations
    define system: [system]
    define creator: [application]
    define can_call_delete_store: [application] or admin
    define can_call_get_store: [application] or admin
    define can_call_check: [application] or reader
    define can_call_expand: [application] or reader
    define can_call_list_objects: [application] or reader
    define can_call_list_users: [application] or reader
    define can_call_read: [application] or reader
    define can_call_read_assertions: [application] or reader or model_writer
    define can_call_read_authorization_models: [application] or reader or model_writer
    define can_call_read_changes: [application] or reader
    define can_call_write: [application] or writer
    define can_call_write_assertions: [application] or model_writer
    define can_call_write_authorization_models: [application] or model_writer
    define model_writer: [application] or admin
    define reader: [application] or admin
    define writer: [application] or admin
    define admin: [application] or creator or admin from system
`

// apiMethods maps bit positions to API methods and their corresponding authz relations.
var apiMethods = []struct {
	method   apimethod.APIMethod
	relation string
}{
	{apimethod.Read, authz.CanCallRead},
	{apimethod.Write, authz.CanCallWrite},
	{apimethod.Check, authz.CanCallCheck},
	{apimethod.ListObjects, authz.CanCallListObjects},
	{apimethod.ListUsers, authz.CanCallListUsers},
	{apimethod.Expand, authz.CanCallExpand},
	{apimethod.ReadChanges, authz.CanCallReadChanges},
	{apimethod.ReadAuthorizationModel, authz.CanCallReadAuthorizationModels},
	{apimethod.WriteAuthorizationModel, authz.CanCallWriteAuthorizationModels},
	{apimethod.ReadAssertions, authz.CanCallReadAssertions},
	{apimethod.WriteAssertions, authz.CanCallWriteAssertions},
	{apimethod.GetStore, authz.CanCallGetStore},
	{apimethod.DeleteStore, authz.CanCallDeleteStore},
}

// FuzzAuthorizationBypass fuzzes the API authorization layer to verify:
// 1. No panics on any input
// 2. If a can_call_* relation is granted, authorization MUST succeed
// 3. If a can_call_* relation is NOT granted, authorization MUST fail
// 4. Empty clientID MUST always fail
// 5. Same inputs produce consistent results
func FuzzAuthorizationBypass(f *testing.F) {
	f.Fuzz(func(t *testing.T, clientID, storeID string, grantBits uint16, apiMethodIdx uint8) {
		// Skip empty storeID - required for tuple construction
		if storeID == "" || clientID == "" {
			return
		}

		// Sanitize storeID to be a valid ULID-like string (alphanumeric, max 26 chars)
		storeID = sanitizeID(storeID)
		if storeID == "" {
			return
		}

		// Select which API method to test
		methodIdx := int(apiMethodIdx) % len(apiMethods)
		selectedMethod := apiMethods[methodIdx]

		// Set up datastore and server
		_, ds, _ := util.MustBootstrapDatastore(t, "memory")
		defer ds.Close()

		s := newEnhancedFuzzServer(ds)
		defer s.Close()

		ctx := context.Background()

		// Create a store for the access control data
		createResp, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "authz-fuzz"})
		if err != nil {
			t.Skip("failed to create store")
			return
		}
		accessControlStoreID := createResp.GetId()

		// Write the access control authorization model
		model := parser.MustTransformDSLToProto(authzModelDSL)
		writeModelResp, err := s.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
			StoreId:         accessControlStoreID,
			TypeDefinitions: model.GetTypeDefinitions(),
			SchemaVersion:   model.GetSchemaVersion(),
			Conditions:       model.GetConditions(),
		})
		if err != nil {
			t.Skip("failed to write authorization model")
			return
		}
		modelID := writeModelResp.GetAuthorizationModelId()

		// Determine which relation to grant based on grantBits
		shouldGrant := grantBits&(1<<uint(methodIdx)) != 0

		if shouldGrant {
			// Write a tuple granting the selected relation to the clientID on the storeID
			_, err = s.Write(ctx, &openfgav1.WriteRequest{
				StoreId:              accessControlStoreID,
				AuthorizationModelId: modelID,
				Writes: &openfgav1.WriteRequestWrites{
					TupleKeys: []*openfgav1.TupleKey{
						{
							User:     "application:" + clientID,
							Relation: selectedMethod.relation,
							Object:   "store:" + storeID,
						},
					},
				},
			})
			if err != nil {
				// Tuple write may fail for invalid characters in clientID/storeID - that's ok
				t.Skip("failed to write tuple")
				return
			}
		}

		// Create the authorizer
		nopLogger := logger.NewNoopLogger()
		authorizer := authz.NewAuthorizer(
			&authz.Config{
				StoreID: accessControlStoreID,
				ModelID: modelID,
			},
			s,
			nopLogger,
		)

		// Build context with auth claims
		authCtx := authclaims.ContextWithAuthClaims(ctx, &authclaims.AuthClaims{
			ClientID: clientID,
		})

		// Test authorization
		authErr := authorizer.Authorize(authCtx, storeID, selectedMethod.method)

		if shouldGrant {
			if authErr != nil {
				t.Errorf("relation %q granted to %q on store %q but Authorize failed: %v",
					selectedMethod.relation, clientID, storeID, authErr)
			}
		} else {
			if authErr == nil {
				t.Errorf("relation %q NOT granted to %q on store %q but Authorize succeeded",
					selectedMethod.relation, clientID, storeID)
			}
		}

		// Consistency check: same call should return same result
		authErr2 := authorizer.Authorize(authCtx, storeID, selectedMethod.method)
		if (authErr == nil) != (authErr2 == nil) {
			t.Errorf("inconsistent authorization results: first=%v, second=%v", authErr, authErr2)
		}

		// Test: empty clientID MUST always fail
		emptyClientCtx := authclaims.ContextWithAuthClaims(ctx, &authclaims.AuthClaims{
			ClientID: "",
		})
		emptyErr := authorizer.Authorize(emptyClientCtx, storeID, selectedMethod.method)
		if emptyErr == nil {
			t.Error("authorization with empty clientID should always fail")
		}

		// Test: missing auth claims MUST fail
		noClaimsErr := authorizer.Authorize(ctx, storeID, selectedMethod.method)
		if noClaimsErr == nil {
			t.Error("authorization without auth claims should always fail")
		}
	})
}

// sanitizeID creates a valid store/client ID from fuzz input.
// OpenFGA IDs must be alphanumeric, max 26 characters.
func sanitizeID(s string) string {
	var result []byte
	for _, b := range []byte(s) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			result = append(result, b)
		}
	}
	if len(result) > 26 {
		result = result[:26]
	}
	return string(result)
}
