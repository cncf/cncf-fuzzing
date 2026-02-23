// Copyright 2021 ADA Logics Ltd
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

package sso

import (
	"encoding/json"

	josejwt "github.com/go-jose/go-jose/v3/jwt"

	"github.com/argoproj/argo-workflows/v3/server/auth/types"
)

func FuzzSSOAuthorize(data []byte) int {
	token := string(data)

	// Parse as signed JWT (JWS)
	parsed, err := josejwt.ParseSigned(token)
	if err == nil {
		var claims types.Claims
		_ = parsed.UnsafeClaimsWithoutVerification(&claims)
	}

	// Parse as encrypted JWT (JWE)
	_, _ = josejwt.ParseEncrypted(token)

	// Test Claims JSON deserialization
	var claims types.Claims
	if err := json.Unmarshal(data, &claims); err == nil {
		_ = claims.Groups
		_ = claims.Email
		_ = claims.Name
		_ = claims.PreferredUsername
	}

	return 1
}
