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

package token

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzToken(data []byte) int {
	f := fuzz.NewConsumer(data)
	rawToken, err := f.GetString()
	if err != nil {
		return 0
	}
	verifyOps := VerifyOptions{}
	err = f.GenerateStruct(&verifyOps)
	if err != nil {
		return 0
	}
	token, err := NewToken(rawToken)
	if err != nil {
		return 0
	}
	token.Verify(verifyOps)
	_, _ = token.VerifySigningKey(verifyOps)
	return 1
}
