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

export CNCFFuzzing="${SRC}/cncf-fuzzing/projects/dapr"

printf "package expr\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/dapr/pkg/expr/registerfuzzdep.go
go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
go mod tidy

cp $CNCFFuzzing/fuzz_expr_test.go $SRC/dapr/pkg/expr/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/expr FuzzExprDecodeString FuzzExprDecodeString

cp $CNCFFuzzing/fuzz_messaging_test.go $SRC/dapr/pkg/messaging/
mv $SRC/dapr/pkg/messaging/direct_messaging_test.go $SRC/dapr/pkg/messaging/direct_messaging_test_fuzz.go 
compile_native_go_fuzzer github.com/dapr/dapr/pkg/messaging FuzzInvokeRemote FuzzInvokeRemote

cp $SRC/dapr/pkg/actors/actors_test.go $SRC/dapr/pkg/actors/actors_test_fuzz.go
cp $SRC/dapr/pkg/actors/actor_test.go $SRC/dapr/pkg/actors/actor_test_fuzz.go
compile_native_go_fuzzer github.com/dapr/dapr/pkg/actors FuzzActorsRuntime FuzzActorsRuntime
