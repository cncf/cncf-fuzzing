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

package fuzzing

import (
	"encoding/json"
	"fmt"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditpolicy "k8s.io/apiserver/pkg/audit/policy"
)

func FuzzLoadPolicyFromBytes(data []byte) int {
	_, _ = auditpolicy.LoadPolicyFromBytes(data)
	return 1
}

func RegistryFuzzer(data []byte) int {
	f := fuzz.NewConsumer(data)
	in := &metav1.UpdateOptions{}
	err := f.GenerateStruct(in)
	if err != nil {
		return 0
	}
	in.TypeMeta.SetGroupVersionKind(metav1.SchemeGroupVersion.WithKind("CreateOptions"))
	out := newCreateOptionsFromUpdateOptions(in)

	inBytes, err := json.Marshal(in)
	if err != nil {
		panic(fmt.Sprintf("failed to json.Marshal(in): %v\n", err))
	}
	outBytes, err := json.Marshal(out)
	if err != nil {
		panic(fmt.Sprintf("failed to json.Marshal(out): %v\n", err))
	}
	inMap := map[string]interface{}{}
	if err := json.Unmarshal(inBytes, &inMap); err != nil {
		panic(fmt.Sprintf("failed to json.Unmarshal(in): %v\n", err))
	}
	outMap := map[string]interface{}{}
	if err := json.Unmarshal(outBytes, &outMap); err != nil {
		panic(fmt.Sprintf("failed to json.Unmarshal(out): %v\n", err))
	}

	// Compare the results.
	inBytes, err = json.Marshal(inMap)
	if err != nil {
		panic(fmt.Sprintf("failed to json.Marshal(in): %v\n", err))
	}
	outBytes, err = json.Marshal(outMap)
	if err != nil {
		panic(fmt.Sprintf("failed to json.Marshal(out): %v\n", err))
	}
	if i, o := string(inBytes), string(outBytes); i != o {
		panic(fmt.Sprintf("output != input:\n  want: %s\n   got: %s\n", i, o))
	}
	return 1

}

func newCreateOptionsFromUpdateOptions(in *metav1.UpdateOptions) *metav1.CreateOptions {
	co := &metav1.CreateOptions{
		DryRun:       in.DryRun,
		FieldManager: in.FieldManager,
	}
	co.TypeMeta.SetGroupVersionKind(metav1.SchemeGroupVersion.WithKind("CreateOptions"))
	return co
}
