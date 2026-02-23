#!/bin/bash -eu
# Copyright 2022 ADA Logics Ltd
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

set -o nounset
set -o pipefail
set -o errexit
set -x

cd "$SRC"
cd /tmp
export GOROOT=/root/.go
wget https://go.dev/dl/go1.25.3.linux-amd64.tar.gz

mkdir temp-go
tar -C temp-go/ -xzf go1.25.3.linux-amd64.tar.gz

rm -r /root/.go
mkdir /root/.go/
mv temp-go/go/* /root/.go/
rm -rf temp-go


cd $SRC/go-118-fuzz-build
go build
mv go-118-fuzz-build $GOPATH/bin/go-118-fuzz-build_v2
pushd cmd/convertLibFuzzerTestcaseToStdLibGo
  go build . && mv convertLibFuzzerTestcaseToStdLibGo $GOPATH/bin/
popd
pushd cmd/addStdLibCorpusToFuzzer
  go build . && mv addStdLibCorpusToFuzzer $GOPATH/bin/
popd

cd $SRC/kubernetes
mkdir $SRC/kubernetes/test/fuzz/fuzzing

export GOTOOLCHAIN=local
export KUBE_FUZZERS=$SRC/cncf-fuzzing/projects/kubernetes

# Move fuzzers from cncf-fuzzing and tests in Kubernetes
#############################################################################

mv $SRC/cncf-fuzzing/projects/kubernetes/roundtrip.go \
   $SRC/kubernetes/staging/src/k8s.io/apimachinery/pkg/api/apitesting/roundtrip/

mv $KUBE_FUZZERS/internal_kubelet_server_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/server/
mv $SRC/kubernetes/pkg/kubelet/server/auth_test.go \
   $SRC/kubernetes/pkg/kubelet/server/auth_test_fuzz.go
mv $SRC/kubernetes/pkg/kubelet/server/server_test.go \
   $SRC/kubernetes/pkg/kubelet/server/server_test_fuzz.go

mv $KUBE_FUZZERS/internal_kubelet_kuberuntime_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/kuberuntime/
mv $KUBE_FUZZERS/internal_kubelet_kuberuntime_fuzz_test.go \
   $SRC/kubernetes/pkg/kubelet/kuberuntime/
mv $SRC/kubernetes/pkg/kubelet/kuberuntime/kuberuntime_manager_test.go \
   $SRC/kubernetes/pkg/kubelet/kuberuntime/kuberuntime_manager_test_fuzz.go


mv $KUBE_FUZZERS/internal_kubelet_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet
mv $KUBE_FUZZERS/internal_kubelet_fuzz_test.go \
   $SRC/kubernetes/pkg/kubelet
mv $SRC/kubernetes/pkg/kubelet/kubelet_pods_test.go \
   $SRC/kubernetes/pkg/kubelet/kubelet_pods_test_fuzz.go
mv $SRC/kubernetes/pkg/kubelet/pod_workers_test.go \
   $SRC/kubernetes/pkg/kubelet/pod_workers_test_fuzz.go
mv $SRC/kubernetes/pkg/kubelet/kubelet_test.go \
   $SRC/kubernetes/pkg/kubelet/kubelet_test_fuzz.go
mv $SRC/kubernetes/pkg/kubelet/kubelet_node_status_test.go \
   $SRC/kubernetes/pkg/kubelet/kubelet_node_status_test_fuzz.go

mv $KUBE_FUZZERS/mount-utils_fuzzer.go \
   $SRC/kubernetes/staging/src/k8s.io/mount-utils/

mv $KUBE_FUZZERS/deployment_util_fuzzer.go \
   $SRC/kubernetes/pkg/controller/deployment/util/
mv $KUBE_FUZZERS/deployment_util_fuzz_test.go \
   $SRC/kubernetes/pkg/controller/deployment/util/

# Copy yaml/json fuzz test wrappers
mv $KUBE_FUZZERS/yaml_fuzz_test.go \
   $SRC/kubernetes/test/fuzz/yaml/
mv $KUBE_FUZZERS/json_fuzz_test.go \
   $SRC/kubernetes/test/fuzz/json/

# Done moving fuzzers and tests
#############################################################################

cd $SRC/kubernetes/test/fuzz/fuzzing

# Copy all fuzz files from cncf-fuzzing (both .go helpers and _test.go wrappers)
rm $KUBE_FUZZERS/parser_fuzzer.go
cp $KUBE_FUZZERS/*.go $SRC/kubernetes/test/fuzz/fuzzing/
cp $KUBE_FUZZERS/*_test.go $SRC/kubernetes/test/fuzz/fuzzing/

# Also copy the native parser fuzzers test
cp $KUBE_FUZZERS/native_go_parser_fuzzers_test.go ./

# Set up go-118-fuzz-build dependency
mkdir -p native_fuzzing && cd native_fuzzing
go install github.com/AdamKorcz/go-118-fuzz-build@latest
printf "package main\nimport ( \n _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n )\n" > register.go

# Run from kubernetes root to preserve workspace context
cd $SRC/kubernetes
go mod tidy -e
go work vendor

# Build all native fuzzers
#############################################################################

# Parser fuzzers (from native_go_parser_fuzzers_test.go)
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseQuantity fuzz_parse_quantity
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzMeta1ParseToLabelSelector fuzz_meta1_parse_to_label_selector
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseSelector fuzz_parse_selector
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzLabelsParse fuzz_labels_parse
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseGroupVersion fuzz_parse_group_version
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseResourceArg fuzz_parse_resource_arg
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseVersion fuzz_parse_version
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParsePrivateKeyPEM fuzz_parse_private_pem
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParsePublicKeysPEM fuzz_parse_public_keys_pem
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseHostPort fuzz_parse_host_port
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzUrlsMatch fuzz_urls_match
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseCSR fuzz_parse_csr
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseEnv fuzz_parse_env
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseQOSReserve fuzz_parse_qos_reserve
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseCPUSet fuzz_parse_cpu_set
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseImageName fuzz_parse_image_name

# Migrated fuzzers (from native_fuzzing_fuzz_test.go)
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzApiRoundtrip fuzz_api_roundtrip
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzDeepCopy fuzz_deep_copy
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzAesRoundtrip fuzz_aes_roundtrip
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzLoadPolicyFromBytes fuzz_load_policy_from_bytes
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzRegistryFuzzer fuzz_registry_fuzzer
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzUnrecognized fuzz_unrecognized
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzRoundTripSpecificKind fuzz_roundtrip_specific_kind
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzControllerRoundtrip fuzz_controller_roundtrip
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzKubeletSchemeRoundtrip fuzz_kubelet_scheme_roundtrip
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzProxySchemeRoundtrip fuzz_proxy_scheme_roundtrip
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzRoundTripType fuzz_roundtrip_type
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzReadLogs fuzz_read_logs
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzRoundtrip fuzz_roundtrip
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzAllValidation fuzz_all_validation
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzCelExprCompile fuzz_compile
compile_native_go_fuzzer_v2 k8s.io/kubernetes/test/fuzz/fuzzing FuzzCelDataCompile fuzz_compiledata

# Internal package fuzzers
compile_native_go_fuzzer_v2 k8s.io/kubernetes/pkg/kubelet/kuberuntime FuzzKubeRuntime fuzz_kube_runtime
compile_native_go_fuzzer_v2 k8s.io/kubernetes/pkg/kubelet FuzzSyncPod fuzz_sync_pod
compile_native_go_fuzzer_v2 k8s.io/kubernetes/pkg/kubelet FuzzStrategicMergePatch fuzz_strategic_merge_patch
compile_native_go_fuzzer_v2 k8s.io/kubernetes/pkg/kubelet FuzzConvertToAPIContainerStatuses fuzz_convert_to_api_container_statuses
compile_native_go_fuzzer_v2 k8s.io/kubernetes/pkg/kubelet FuzzHandlePodCleanups fuzz_handle_pod_cleanups
compile_native_go_fuzzer_v2 k8s.io/kubernetes/pkg/kubelet FuzzMakeEnvironmentVariables fuzz_make_environment_variables
compile_native_go_fuzzer_v2 k8s.io/kubernetes/pkg/controller/deployment/util FuzzEntireDeploymentUtil fuzz_entire_deployment_util

# Auto-generated marshaling fuzzer (non-coverage only, kept as compile_go_fuzzer)
cd $SRC/kubernetes
if [ "$SANITIZER" != "coverage" ]; then
   grep -r ") Marshal()" . > $SRC/grep_result.txt
   mv $SRC/cncf-fuzzing/projects/kubernetes/autogenerate.py ./
   python3 autogenerate.py --input_file $SRC/grep_result.txt
   mv api_marshaling_fuzzer.go $SRC/kubernetes/test/fuzz/fuzzing/
fi

if [ "$SANITIZER" != "coverage" ]; then
   compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzApiMarshaling fuzz_api_marshaling
fi
