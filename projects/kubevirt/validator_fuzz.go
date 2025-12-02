// Copyright 2025 the cncf-fuzzing authors
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

package definitions

import "k8s.io/apimachinery/pkg/runtime/schema"

// noopValidator is a stub for fuzzing that skips OpenAPI schema validation.
// This avoids the 111-second initialization of ComposeAPIDefinitions().
type noopValidator struct{}

func (n *noopValidator) Validate(gvk schema.GroupVersionKind, obj map[string]interface{}) []error {
	return nil
}

func (n *noopValidator) ValidateSpec(gvk schema.GroupVersionKind, obj map[string]interface{}) []error {
	return nil
}

func (n *noopValidator) ValidateStatus(gvk schema.GroupVersionKind, obj map[string]interface{}) []error {
	return nil
}

var Validator = &noopValidator{}
