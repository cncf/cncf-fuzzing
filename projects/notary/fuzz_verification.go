// Copyright 2023 the cncf-fuzzing authors
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

package verifier

import (
	"context"
	"testing"

	notation "github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/internal/mock"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzVerify(f *testing.F) {
	f.Fuzz(func(t *testing.T, policyDocBytes []byte) {
		ff := fuzz.NewConsumer(policyDocBytes)
		policyDoc := trustpolicy.Document{}
		ff.GenerateStruct(&policyDoc)
		policyDoc.Version = "1.0"
		err := policyDoc.Validate()
		if err != nil {
			t.Skip()
		}

		td := t.TempDir()
		dir.UserConfigDir = td

		v, err := New(&policyDoc, truststore.NewX509TrustStore(dir.ConfigFS()), mock.PluginManager{})
		if err != nil {
			t.Skip()
		}
		_, _, _ = notation.Verify(context.Background(), v, mock.NewRepository(), notation.RemoteVerifyOptions{})
	})
}
