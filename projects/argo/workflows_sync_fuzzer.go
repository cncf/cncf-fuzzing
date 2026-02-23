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

package sync

import (
	"fmt"

	"github.com/argoproj/argo-workflows/v3/util/logging"
)

func FuzzDecodeLockName(data []byte) int {
	ctx := logging.NewSlogLogger(logging.Info, logging.Text).NewBackgroundContext()
	lock, err := DecodeLockName(ctx, string(data))
	if err != nil {
		return 0
	}
	// Roundtrip: encode back to string, then decode again
	encoded := lock.String(ctx)
	lock2, err := DecodeLockName(ctx, encoded)
	if err != nil {
		panic(fmt.Sprintf("roundtrip decode failed: input=%q encoded=%q err=%v", string(data), encoded, err))
	}
	// Verify fields match
	if lock.GetNamespace() != lock2.GetNamespace() ||
		lock.GetResourceName() != lock2.GetResourceName() ||
		lock.GetKey() != lock2.GetKey() {
		panic(fmt.Sprintf("roundtrip mismatch: ns=%q/%q res=%q/%q key=%q/%q",
			lock.GetNamespace(), lock2.GetNamespace(),
			lock.GetResourceName(), lock2.GetResourceName(),
			lock.GetKey(), lock2.GetKey()))
	}
	return 1
}
