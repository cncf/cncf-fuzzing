#!/bin/bash -eu
# Copyright 2022 Ada Logics Ltd
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

export CNCFFuzzing="${SRC}/cncf-fuzzing/projects/knative"

printf "package metrics\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/pkg/metrics/registerfuzzdep.go
go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
go mod tidy && go mod vendor
cp $CNCFFuzzing/json_fuzzer.go $SRC/pkg/webhook/json/
mv $SRC/pkg/webhook/json/decode_test.go $SRC/pkg/webhook/json/decode_test_fuzz.go
compile_go_fuzzer knative.dev/pkg/webhook/json FuzzJsonDecode fuzz_json_decode

cp $CNCFFuzzing/fuzz_configmaps.go $SRC/pkg/webhook/configmaps/
mv $SRC/pkg/webhook/configmaps/configmaps_test.go $SRC/pkg/webhook/configmaps/configmaps_fuzz.go
compile_native_go_fuzzer knative.dev/pkg/webhook/configmaps FuzzAdmit FuzzAdmit

cp $CNCFFuzzing/fuzz_pkg_metrics.go $SRC/pkg/metrics/
compile_native_go_fuzzer knative.dev/pkg/metrics FuzzNewObservabilityConfigFromConfigMap FuzzNewObservabilityConfigFromConfigMap

cp $CNCFFuzzing/fuzz_pkg_kmeta.go $SRC/pkg/kmeta/
compile_native_go_fuzzer knative.dev/pkg/kmeta FuzzChildName FuzzChildName

cp $CNCFFuzzing/fuzz_pkg_websocket.go $SRC/pkg/websocket/
mv $SRC/pkg/websocket/connection_test.go $SRC/pkg/websocket/connection_fuzz.go
compile_native_go_fuzzer knative.dev/pkg/websocket FuzzSendRawMessage FuzzSendRawMessage

# serving fuzzers
cp $CNCFFuzzing/fuzz_activatornet.go $SRC/serving/pkg/activator/net/
cd $SRC/serving
mv pkg/activator/net/throttler_test.go pkg/activator/net/throttler_test_fuzz.go
mv pkg/activator/net/revision_backends_test.go pkg/activator/net/revision_backends_test_fuzz.go
printf "package net\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/serving/pkg/activator/net/registerfuzzdep.go
go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
go mod tidy && go mod vendor
compile_native_go_fuzzer knative.dev/serving/pkg/activator/net FuzzNewRevisionThrottler FuzzNewRevisionThrottler

cp $CNCFFuzzing/fuzz_serving_route_reconciler.go $SRC/serving/pkg/reconciler/route/
mv $SRC/serving/pkg/reconciler/route/table_test.go $SRC/serving/pkg/reconciler/route/table_test_fuzz.go
mv $SRC/serving/pkg/reconciler/route/route_test.go $SRC/serving/pkg/reconciler/route/route_test_fuzz.go
mv $SRC/serving/pkg/reconciler/route/reconcile_resources_test.go $SRC/serving/pkg/reconciler/route/reconcile_resources_test_fuzz.go
compile_native_go_fuzzer knative.dev/serving/pkg/reconciler/route FuzzRouteReconciler FuzzRouteReconciler

cp $CNCFFuzzing/fuzz_domains.go $SRC/serving/pkg/reconciler/route/domains/
compile_native_go_fuzzer knative.dev/serving/pkg/reconciler/route/domains FuzzDomainNameFromTemplate FuzzDomainNameFromTemplate 

cp $CNCFFuzzing/fuzz_validation.go $SRC/serving/pkg/apis/serving/v1/
compile_native_go_fuzzer knative.dev/serving/pkg/apis/serving/v1 FuzzValidation FuzzValidation 

cd $SRC
git clone https://github.com/knative/eventing --depth=1
cd eventing
cp $CNCFFuzzing/fuzz_messaging_v1.go $SRC/eventing/pkg/apis/messaging/v1/
printf "package v1\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/eventing/pkg/apis/messaging/v1/registerfuzzdep.go
go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
go mod tidy && go mod vendor
mv $SRC/eventing/pkg/apis/messaging/v1/roundtrip_test.go $SRC/eventing/pkg/apis/messaging/v1/roundtrip_test_fuzz.go
compile_native_go_fuzzer knative.dev/eventing/pkg/apis/messaging/v1 FuzzMessagingRoundTripTypesToJSON FuzzMessagingRoundTripTypesToJSON
