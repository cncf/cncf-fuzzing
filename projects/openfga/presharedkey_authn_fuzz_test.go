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

	"google.golang.org/grpc/metadata"

	"github.com/openfga/openfga/internal/authn"
	"github.com/openfga/openfga/internal/authn/presharedkey"
)

// FuzzPresharedKeyAuthentication fuzzes the preshared key authenticator to verify:
// 1. No panics on any input
// 2. If token matches a valid key, authentication succeeds
// 3. If token doesn't match any valid key, authentication fails with ErrUnauthenticated
// 4. If no bearer token in context, authentication fails with ErrMissingBearerToken
func FuzzPresharedKeyAuthentication(f *testing.F) {
	f.Fuzz(func(t *testing.T, key1, key2, key3, testToken string, configBits uint8) {
		// Build valid keys list based on configBits
		var validKeys []string
		if configBits&0x01 != 0 && key1 != "" {
			validKeys = append(validKeys, key1)
		}
		if configBits&0x02 != 0 && key2 != "" {
			validKeys = append(validKeys, key2)
		}
		if configBits&0x04 != 0 && key3 != "" {
			validKeys = append(validKeys, key3)
		}

		// Need at least one valid key
		if len(validKeys) == 0 {
			// Use key1 if non-empty, otherwise skip
			if key1 == "" {
				return
			}
			validKeys = []string{key1}
		}

		pka, err := presharedkey.NewPresharedKeyAuthenticator(validKeys)
		if err != nil {
			t.Fatalf("failed to create authenticator: %v", err)
		}
		defer pka.Close()

		// Build set of valid keys for oracle checking
		validKeySet := make(map[string]struct{})
		for _, k := range validKeys {
			validKeySet[k] = struct{}{}
		}

		// Test 1: Authentication with bearer token
		md := metadata.Pairs("authorization", "Bearer "+testToken)
		ctx := metadata.NewIncomingContext(context.Background(), md)

		claims, err := pka.Authenticate(ctx)
		_, tokenIsValid := validKeySet[testToken]

		if tokenIsValid {
			// Token matches a valid key - MUST succeed
			if err != nil {
				t.Errorf("token matches valid key but authentication failed: %v", err)
			}
			if claims == nil {
				t.Error("authentication succeeded but claims are nil")
			}
		} else {
			// Token doesn't match - MUST fail with ErrUnauthenticated
			if err == nil {
				t.Error("token doesn't match any valid key but authentication succeeded")
			}
			if err != nil && err.Error() != authn.ErrUnauthenticated.Error() {
				t.Errorf("expected ErrUnauthenticated, got: %v", err)
			}
		}

		// Test 2: Authentication without bearer token - MUST fail with ErrMissingBearerToken
		emptyCtx := context.Background()
		claims, err = pka.Authenticate(emptyCtx)
		if err == nil {
			t.Error("authentication without bearer token should fail")
		}
		if claims != nil {
			t.Error("claims should be nil when no bearer token")
		}
		if err != nil && err.Error() != authn.ErrMissingBearerToken.Error() {
			t.Errorf("expected ErrMissingBearerToken, got: %v", err)
		}

		// Test 3: Authentication with wrong authorization scheme
		mdBasic := metadata.Pairs("authorization", "Basic "+testToken)
		ctxBasic := metadata.NewIncomingContext(context.Background(), mdBasic)
		claims, err = pka.Authenticate(ctxBasic)
		if err == nil {
			t.Error("authentication with Basic scheme should fail")
		}
		if claims != nil {
			t.Error("claims should be nil with wrong auth scheme")
		}
	})
}
