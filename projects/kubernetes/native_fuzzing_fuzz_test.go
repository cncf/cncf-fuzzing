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

package fuzzing

import "testing"

func FuzzApiRoundtrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzApiRoundtrip(data)
	})
}

func FuzzRoundtrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzRoundtrip(data)
	})
}

func FuzzAllValidation(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzAllValidation(data)
	})
}

func FuzzDeepCopy(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzDeepCopy(data)
	})
}

func FuzzUnrecognized(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzUnrecognized(data)
	})
}

func FuzzAesRoundtrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzAesRoundtrip(data)
	})
}

func FuzzRoundTripSpecificKind(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzRoundTripSpecificKind(data)
	})
}

func FuzzControllerRoundtrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzControllerRoundtrip(data)
	})
}

func FuzzKubeletSchemeRoundtrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzKubeletSchemeRoundtrip(data)
	})
}

func FuzzProxySchemeRoundtrip(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzProxySchemeRoundtrip(data)
	})
}

func FuzzRoundTripType(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzRoundTripType(data)
	})
}

func FuzzReadLogs(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzReadLogs(data)
	})
}

func FuzzLoadPolicyFromBytes(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzLoadPolicyFromBytes(data)
	})
}

func FuzzRegistryFuzzer(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		doRegistryFuzzer(data)
	})
}

func FuzzCelExprCompile(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCelCompile(data)
	})
}

func FuzzCelDataCompile(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCelDataCompile(data)
	})
}
