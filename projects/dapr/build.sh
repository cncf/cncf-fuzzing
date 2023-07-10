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

# Delete build comment ("unit")
sed '1d' -i $SRC/dapr/pkg/diagnostics/diagtestutils/testutils.go

export CNCFFuzzing="${SRC}/cncf-fuzzing/projects/dapr"

rm $SRC/dapr/pkg/http/*_test.go # test files cause some issues and we don't need them
printf "package expr\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/dapr/pkg/expr/registerfuzzdep.go
go mod edit -replace github.com/adalogics/go-fuzz-headers=github.com/adamkorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
go mod tidy
mv $SRC/dapr/pkg/actors/actors_test.go $SRC/dapr/pkg/actors/actors_test_fuzz.go
mv $SRC/dapr/pkg/actors/actor_test.go $SRC/dapr/pkg/actors/actor_test_fuzz.go

cp $CNCFFuzzing/fuzz_expr_test.go $SRC/dapr/pkg/expr/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/expr FuzzExprDecodeString FuzzExprDecodeString

cp $CNCFFuzzing/fuzz_injector_test.go $SRC/dapr/pkg/injector/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/injector FuzzHandleRequest FuzzHandleRequest

cp $CNCFFuzzing/fuzz_placement_raft_test.go $SRC/dapr/pkg/placement/raft/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/placement/raft FuzzFSMPlacementState FuzzFSMPlacementState

mv $SRC/dapr/pkg/runtime/runtime_test.go $SRC/dapr/pkg/runtime/runtime_test_fuzz.go
cp $CNCFFuzzing/fuzz_runtime_test.go $SRC/dapr/pkg/runtime/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/runtime FuzzDaprRuntime FuzzDaprRuntime

cp $CNCFFuzzing/fuzz_messaging_test.go $SRC/dapr/pkg/messaging/
mv $SRC/dapr/pkg/messaging/direct_messaging_test.go $SRC/dapr/pkg/messaging/direct_messaging_test_fuzz.go 
compile_native_go_fuzzer github.com/dapr/dapr/pkg/messaging FuzzInvokeRemote FuzzInvokeRemote

cp $CNCFFuzzing/fuzz_actors_test.go $SRC/dapr/pkg/actors/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/actors FuzzActorsRuntime FuzzActorsRuntime unit
cp $CNCFFuzzing/fuzz_acl_test.go $SRC/dapr/pkg/acl/
cp $CNCFFuzzing/fuzz_acl_apply_test.go $SRC/dapr/pkg/acl/
go mod tidy
compile_native_go_fuzzer github.com/dapr/dapr/pkg/acl FuzzParseAccessControlSpec FuzzParseAccessControlSpec
compile_native_go_fuzzer github.com/dapr/dapr/pkg/acl FuzzPurellTest FuzzPurellTest
compile_native_go_fuzzer github.com/dapr/dapr/pkg/acl FuzzIsOperationAllowedByAccessControlPolicy FuzzIsOperationAllowedByAccessControlPolicy

cp $CNCFFuzzing/fuzz_http_server_test.go $SRC/dapr/pkg/http/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzHTTPRegex FuzHTTPRegex

cp $CNCFFuzzing/fuzz_http_server_endpoint_test.go $SRC/dapr/pkg/http/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzIsEndpointAllowed FuzzIsEndpointAllowed

cp $CNCFFuzzing/fuzz_http_endpoints_test.go $SRC/dapr/pkg/http/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnPostStateTransaction FuzzOnPostStateTransaction
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnBulkPublish FuzzOnBulkPublish
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnPublish FuzzOnPublish
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnDirectActorMessage FuzzOnDirectActorMessage
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnDeleteActorTimer FuzzOnDeleteActorTimer
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnGetActorReminder FuzzOnGetActorReminder
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnActorStateTransaction FuzzOnActorStateTransaction
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnDeleteActorReminder FuzzOnDeleteActorReminder
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnCreateActorTimer FuzzOnCreateActorTimer
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnRenameActorReminder FuzzOnRenameActorReminder 
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnCreateActorReminder FuzzOnCreateActorReminder
compile_native_go_fuzzer github.com/dapr/dapr/pkg/http FuzzOnDirectMessage FuzzOnDirectMessage

rm $SRC/dapr/pkg/grpc/*_test.go
cp $CNCFFuzzing/fuzz_grpc_endpoints_test.go $SRC/dapr/pkg/grpc/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/grpc FuzzPublishEvent FuzzPublishEvent
compile_native_go_fuzzer github.com/dapr/dapr/pkg/grpc FuzzInvokeService FuzzInvokeService
compile_native_go_fuzzer github.com/dapr/dapr/pkg/grpc FuzzBulkPublishEventAlpha1 FuzzBulkPublishEventAlpha1
compile_native_go_fuzzer github.com/dapr/dapr/pkg/grpc FuzzStateEndpoints FuzzStateEndpoints
compile_native_go_fuzzer github.com/dapr/dapr/pkg/grpc FuzzActorEndpoints FuzzActorEndpoints
compile_native_go_fuzzer github.com/dapr/dapr/pkg/grpc FuzzGetConfiguration FuzzGetConfiguration

cp $CNCFFuzzing/fuzz_sidecar_test.go $SRC/dapr/pkg/injector/sidecar/
compile_native_go_fuzzer github.com/dapr/dapr/pkg/injector/sidecar FuzzParseEnvString FuzzParseEnvString

cd $SRC/kit
cp $CNCFFuzzing/fuzz_kit_crypto_test.go ./crypto
cp $CNCFFuzzing/fuzz_aescbcaead_test.go ./crypto/aescbcaead/
cp $CNCFFuzzing/pkcs7_padding.go ./crypto/padding/
printf "package expr\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/dapr/pkg/expr/registerfuzzdep.go
go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
go get github.com/lestrrat-go/jwx/v2@246dde86988b21ca0585fc34146e3f3c13f46bc1
go mod tidy
go get github.com/AdamKorcz/go-118-fuzz-build/testing
compile_native_go_fuzzer github.com/dapr/kit/crypto FuzzCryptoKeysJson FuzzCryptoKeysJson
compile_native_go_fuzzer github.com/dapr/kit/crypto FuzzCryptoKeysRaw FuzzCryptoKeysRaw
compile_native_go_fuzzer github.com/dapr/kit/crypto FuzzCryptoKeysAny FuzzCryptoKeys
compile_native_go_fuzzer github.com/dapr/kit/crypto FuzzSymmetric FuzzSymmetric
compile_native_go_fuzzer github.com/dapr/kit/crypto/aescbcaead FuzzAescbcaead FuzzAescbcaead

cd $SRC
git clone --depth=1 https://github.com/dapr/components-contrib
git clone --depth=1 https://github.com/AdamKorcz/dubbo-go-hessian2 --branch=fix1
cd components-contrib
go mod edit -replace 
go mod edit -replace github.com/apache/dubbo-go-hessian2=$SRC/dubbo-go-hessian2
go mod edit -replace github.com/adalogics/go-fuzz-headers=github.com/adamkorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
cp $CNCFFuzzing/fuzz_components_contrib_dubbo_test.go ./bindings/dubbo/
cp $CNCFFuzzing/fuzz_components_contrib_mqtt3_test.go ./pubsub/mqtt3/
cp $CNCFFuzzing/fuzz_components_contrib_state_query_test.go ./state/query/
cp $CNCFFuzzing/fuzz_components_contrib_state_test.go ./state/
cp $CNCFFuzzing/fuzz_components_contrib_metadata_test.go ./metadata/
cp $CNCFFuzzing/fuzz_components_contrib_ratelimiter_test.go ./middleware/http/ratelimit/
cp $CNCFFuzzing/fuzz_components_contrib_graphql_test.go ./bindings/graphql/
cp $CNCFFuzzing/fuzz_components_contrib_azure_eventgrid_test.go ./bindings/azure/eventgrid/
cp $CNCFFuzzing/fuzz_components_contrib_pubsub_pulsar_test.go ./pubsub/pulsar/
printf "package metadata\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./metadata/registerfuzzdep.go
go mod tidy

compile_native_go_fuzzer github.com/dapr/components-contrib/bindings/dubbo FuzzDubboSerialization FuzzDubboSerialization
compile_native_go_fuzzer github.com/dapr/components-contrib/pubsub/mqtt3 FuzzAddTopic FuzzAddTopic
compile_native_go_fuzzer github.com/dapr/components-contrib/state/query FuzzQuery FuzzQuery
compile_native_go_fuzzer github.com/dapr/components-contrib/state FuzzCheckRequestOptions FuzzCheckRequestOptions
compile_native_go_fuzzer github.com/dapr/components-contrib/metadata FuzzDecodeMetadata FuzzDecodeMetadata
compile_native_go_fuzzer github.com/dapr/components-contrib/middleware/http/ratelimit FuzzRLTest FuzzRLTest
compile_native_go_fuzzer github.com/dapr/components-contrib/bindings/graphql FuzzGraphqlRETest FuzzGraphqlRETest
compile_native_go_fuzzer github.com/dapr/components-contrib/bindings/azure/eventgrid FuzzAzureEventGridTest FuzzAzureEventGridTest
compile_native_go_fuzzer github.com/dapr/components-contrib/pubsub/pulsar FuzzAvroTest FuzzAvroTest
