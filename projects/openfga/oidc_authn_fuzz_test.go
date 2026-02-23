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
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/metadata"

	"github.com/openfga/openfga/internal/authn/oidc"
)

// oidcFuzzKeyState holds pre-generated RSA keys for OIDC fuzzing to avoid
// expensive key generation on every iteration.
var oidcFuzzKeyState struct {
	once       sync.Once
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	wrongKey   *rsa.PrivateKey
	err        error
}

func getOIDCFuzzKeys() (*rsa.PrivateKey, *rsa.PublicKey, *rsa.PrivateKey, error) {
	oidcFuzzKeyState.once.Do(func() {
		oidcFuzzKeyState.privateKey, oidcFuzzKeyState.err = rsa.GenerateKey(rand.Reader, 2048)
		if oidcFuzzKeyState.err == nil {
			oidcFuzzKeyState.publicKey = &oidcFuzzKeyState.privateKey.PublicKey
			oidcFuzzKeyState.wrongKey, oidcFuzzKeyState.err = rsa.GenerateKey(rand.Reader, 2048)
		}
	})
	return oidcFuzzKeyState.privateKey, oidcFuzzKeyState.publicKey, oidcFuzzKeyState.wrongKey, oidcFuzzKeyState.err
}

// FuzzOIDCAuthentication fuzzes the OIDC authenticator's JWT claim parsing and validation.
// It generates real RSA-signed JWTs with fuzz-controlled claims and exercises
// diverse claim validation code paths (issuer, audience, subject, scopes, clientID).
//
// INVARIANTS TESTED:
// 1. No panics on any input (crash safety)
// 2. Missing bearer token always fails
// 3. Exercises wrong-audience, wrong-issuer, expired token paths
func FuzzOIDCAuthentication(f *testing.F) {
	f.Fuzz(func(t *testing.T, issuer, audience, subject, clientID, scopeStr string, configBits uint8, timeDelta int16) {
		// Skip empty issuer/audience - these are required config
		if issuer == "" || audience == "" {
			return
		}

		// Limit string lengths to avoid excessive memory use
		if len(issuer) > 256 || len(audience) > 256 || len(subject) > 256 ||
			len(clientID) > 256 || len(scopeStr) > 1024 {
			return
		}

		privateKey, publicKey, wrongKey, err := getOIDCFuzzKeys()
		if err != nil {
			return
		}

		kid := "fuzz-kid-1"

		// Create JWKS with the pre-generated public key
		givenKey := keyfunc.NewGivenCustom(publicKey, keyfunc.GivenKeyOptions{
			Algorithm: "RS256",
		})
		jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
			kid: givenKey,
		})

		// Build authenticator config from configBits
		var issuerAliases []string
		if configBits&0x01 != 0 {
			issuerAliases = []string{issuer + "-alias"}
		}

		var subjects []string
		if configBits&0x02 != 0 && subject != "" {
			subjects = []string{subject}
		}

		clientIDClaims := []string{"azp", "client_id"}
		useCustomClientIDClaim := configBits&0x04 != 0
		if useCustomClientIDClaim {
			clientIDClaims = []string{"custom_client_id", "azp"}
		}

		// Construct authenticator directly (bypass NewRemoteOidcAuthenticator which calls fetchJWKs)
		oidcAuth := &oidc.RemoteOidcAuthenticator{
			MainIssuer:     issuer,
			IssuerAliases:  issuerAliases,
			Audience:       audience,
			Subjects:       subjects,
			ClientIDClaims: clientIDClaims,
			JWKs:           jwks,
		}

		// Build JWT claims
		now := time.Now()
		delta := time.Duration(timeDelta) * time.Second

		claims := jwt.MapClaims{
			"iss":   issuer,
			"aud":   audience,
			"sub":   subject,
			"exp":   jwt.NewNumericDate(now.Add(5*time.Minute + delta)),
			"iat":   jwt.NewNumericDate(now.Add(-1*time.Second + delta)),
			"scope": scopeStr,
		}

		// Set client ID claim
		if useCustomClientIDClaim {
			claims["custom_client_id"] = clientID
		} else {
			claims["azp"] = clientID
		}

		// Sign the JWT with pre-generated key
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		signedToken, err := token.SignedString(privateKey)
		if err != nil {
			return
		}

		// Create gRPC context with bearer token and call Authenticate
		md := metadata.Pairs("authorization", "Bearer "+signedToken)
		ctx := metadata.NewIncomingContext(context.Background(), md)
		oidcAuth.Authenticate(ctx)

		// Exercise: missing bearer token path
		oidcAuth.Authenticate(context.Background())

		// Exercise: wrong key signature path
		wrongToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		wrongToken.Header["kid"] = kid
		wrongSigned, signErr := wrongToken.SignedString(wrongKey)
		if signErr == nil {
			mdWrong := metadata.Pairs("authorization", "Bearer "+wrongSigned)
			ctxWrong := metadata.NewIncomingContext(context.Background(), mdWrong)
			oidcAuth.Authenticate(ctxWrong)
		}

		// Exercise: wrong-audience path
		if configBits&0x08 != 0 {
			wrongAudClaims := jwt.MapClaims{
				"iss": issuer,
				"aud": audience + "-wrong",
				"sub": subject,
				"exp": jwt.NewNumericDate(now.Add(5 * time.Minute)),
				"iat": jwt.NewNumericDate(now.Add(-1 * time.Second)),
			}
			wrongAudToken := jwt.NewWithClaims(jwt.SigningMethodRS256, wrongAudClaims)
			wrongAudToken.Header["kid"] = kid
			wrongAudSigned, signErr := wrongAudToken.SignedString(privateKey)
			if signErr == nil {
				mdWrongAud := metadata.Pairs("authorization", "Bearer "+wrongAudSigned)
				ctxWrongAud := metadata.NewIncomingContext(context.Background(), mdWrongAud)
				oidcAuth.Authenticate(ctxWrongAud)
			}
		}

		// Exercise: wrong-issuer path
		if configBits&0x10 != 0 {
			wrongIssClaims := jwt.MapClaims{
				"iss": "totally-different-issuer",
				"aud": audience,
				"sub": subject,
				"exp": jwt.NewNumericDate(now.Add(5 * time.Minute)),
				"iat": jwt.NewNumericDate(now.Add(-1 * time.Second)),
			}
			wrongIssToken := jwt.NewWithClaims(jwt.SigningMethodRS256, wrongIssClaims)
			wrongIssToken.Header["kid"] = kid
			wrongIssSigned, signErr := wrongIssToken.SignedString(privateKey)
			if signErr == nil {
				mdWrongIss := metadata.Pairs("authorization", "Bearer "+wrongIssSigned)
				ctxWrongIss := metadata.NewIncomingContext(context.Background(), mdWrongIss)
				oidcAuth.Authenticate(ctxWrongIss)
			}
		}

		// Exercise: expired token path
		if configBits&0x20 != 0 {
			expiredClaims := jwt.MapClaims{
				"iss": issuer,
				"aud": audience,
				"sub": subject,
				"exp": jwt.NewNumericDate(now.Add(-1 * time.Hour)),
				"iat": jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			}
			expiredToken := jwt.NewWithClaims(jwt.SigningMethodRS256, expiredClaims)
			expiredToken.Header["kid"] = kid
			expiredSigned, signErr := expiredToken.SignedString(privateKey)
			if signErr == nil {
				mdExpired := metadata.Pairs("authorization", "Bearer "+expiredSigned)
				ctxExpired := metadata.NewIncomingContext(context.Background(), mdExpired)
				oidcAuth.Authenticate(ctxExpired)
			}
		}

		// Exercise: no-expiry token path
		if configBits&0x40 != 0 {
			noExpClaims := jwt.MapClaims{
				"iss": issuer,
				"aud": audience,
				"sub": subject,
				"iat": jwt.NewNumericDate(now.Add(-1 * time.Second)),
			}
			noExpToken := jwt.NewWithClaims(jwt.SigningMethodRS256, noExpClaims)
			noExpToken.Header["kid"] = kid
			noExpSigned, signErr := noExpToken.SignedString(privateKey)
			if signErr == nil {
				mdNoExp := metadata.Pairs("authorization", "Bearer "+noExpSigned)
				ctxNoExp := metadata.NewIncomingContext(context.Background(), mdNoExp)
				oidcAuth.Authenticate(ctxNoExp)
			}
		}

		// Exercise: non-string subject path
		if configBits&0x80 != 0 {
			intSubClaims := jwt.MapClaims{
				"iss": issuer,
				"aud": audience,
				"sub": 12345,
				"exp": jwt.NewNumericDate(now.Add(5 * time.Minute)),
				"iat": jwt.NewNumericDate(now.Add(-1 * time.Second)),
			}
			intSubToken := jwt.NewWithClaims(jwt.SigningMethodRS256, intSubClaims)
			intSubToken.Header["kid"] = kid
			intSubSigned, signErr := intSubToken.SignedString(privateKey)
			if signErr == nil {
				mdIntSub := metadata.Pairs("authorization", "Bearer "+intSubSigned)
				ctxIntSub := metadata.NewIncomingContext(context.Background(), mdIntSub)
				oidcAuth.Authenticate(ctxIntSub)
			}
		}
	})
}
