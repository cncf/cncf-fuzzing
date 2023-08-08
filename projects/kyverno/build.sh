#!/bin/bash -eu
# Copyright 2023 the cncf-fuzzing authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

export CNCFFuzzing="${SRC}/cncf-fuzzing/projects/kyverno"

cp $CNCFFuzzing/fuzz_policy_test.go $SRC/kyverno/pkg/validation/policy/
cp $CNCFFuzzing/fuzz_anchor_test.go $SRC/kyverno/pkg/engine/anchor/

printf "package engine\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/kyverno/pkg/engine/registerfuzzdep.go
go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
go mod tidy

cp $CNCFFuzzing/fuzz_evaluate_test.go $SRC/kyverno/pkg/engine/variables
compile_native_go_fuzzer github.com/kyverno/kyverno/pkg/engine/variables FuzzEvaluate FuzzEvaluate

cp $CNCFFuzzing/fuzz_v2beta1_test.go $SRC/kyverno/api/kyverno/v2beta1/
compile_native_go_fuzzer github.com/kyverno/kyverno/api/kyverno/v2beta1 FuzzV2beta1PolicyValidate FuzzV2beta1PolicyValidate
compile_native_go_fuzzer github.com/kyverno/kyverno/api/kyverno/v2beta1 FuzzV2beta1ImageVerification FuzzV2beta1ImageVerification
compile_native_go_fuzzer github.com/kyverno/kyverno/api/kyverno/v2beta1 FuzzV2beta1MatchResources FuzzV2beta1MatchResources
compile_native_go_fuzzer github.com/kyverno/kyverno/api/kyverno/v2beta1 FuzzV2beta1ClusterPolicy FuzzV2beta1ClusterPolicy

cp $CNCFFuzzing/fuzz_v1_test.go $SRC/kyverno/api/kyverno/v1/
compile_native_go_fuzzer github.com/kyverno/kyverno/api/kyverno/v1 FuzzV1PolicyValidate FuzzV2beta1PolicyValidate
compile_native_go_fuzzer github.com/kyverno/kyverno/api/kyverno/v1 FuzzV1ImageVerification FuzzV2beta1ImageVerification
compile_native_go_fuzzer github.com/kyverno/kyverno/api/kyverno/v1 FuzzV1MatchResources FuzzV2beta1MatchResources
compile_native_go_fuzzer github.com/kyverno/kyverno/api/kyverno/v1 FuzzV1ClusterPolicy FuzzV2beta1ClusterPolicy

cp $CNCFFuzzing/fuzz_engine_test.go $SRC/kyverno/pkg/engine/
compile_native_go_fuzzer github.com/kyverno/kyverno/pkg/engine FuzzVerifyImageAndPatchTest FuzzVerifyImageAndPatchTest
compile_native_go_fuzzer github.com/kyverno/kyverno/pkg/engine FuzzEngineValidateTest FuzzEngineValidateTest
compile_native_go_fuzzer github.com/kyverno/kyverno/pkg/engine FuzzMutateTest FuzzMutateTest
compile_native_go_fuzzer github.com/kyverno/kyverno/pkg/validation/policy FuzzValidatePolicy FuzzValidatePolicy
compile_native_go_fuzzer github.com/kyverno/kyverno/pkg/engine/anchor FuzzAnchorParseTest FuzzAnchorParseTest

cp $CNCFFuzzing/fuzz_engine_api_test.go $SRC/kyverno/pkg/engine/api/
compile_native_go_fuzzer github.com/kyverno/kyverno/pkg/engine/api FuzzEngineResponse FuzzEngineResponse
