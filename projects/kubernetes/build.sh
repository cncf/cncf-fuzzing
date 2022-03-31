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


# Autogenerate the marshaling fuzzer
cd $SRC/kubernetes



go get github.com/AdaLogics/go-fuzz-headers@latest

mkdir $SRC/kubernetes/test/fuzz/fuzzing
grep -r ") Marshal()" . > $SRC/grep_result.txt
mv $SRC/cncf-fuzzing/projects/kubernetes/autogenerate.py ./
python3 autogenerate.py --input_file $SRC/grep_result.txt
mv api_marshaling_fuzzer.go $SRC/kubernetes/test/fuzz/fuzzing/

export KUBE_FUZZERS=$SRC/cncf-fuzzing/projects/kubernetes

mv $KUBE_FUZZERS/internal_kubelet_server_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/server/
mv $SRC/kubernetes/pkg/kubelet/server/auth_test.go \
   $SRC/kubernetes/pkg/kubelet/server/auth_test_fuzz.go
mv $SRC/kubernetes/pkg/kubelet/server/server_test.go \
   $SRC/kubernetes/pkg/kubelet/server/server_test_fuzz.go

mv $KUBE_FUZZERS/internal_kubelet_kuberuntime_fuzzer.go \
   $SRC/kubernetes/pkg/kubelet/kuberuntime/
mv $SRC/kubernetes/pkg/kubelet/kuberuntime/kuberuntime_manager_test.go \
   $SRC/kubernetes/pkg/kubelet/kuberuntime/kuberuntime_manager_test_fuzz.go


mv $KUBE_FUZZERS/internal_kubelet_fuzzer.go \
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


cd $SRC/kubernetes/test/fuzz/fuzzing
cp $KUBE_FUZZERS/native_go_parser_fuzzers_test.go ./
mkdir native_fuzzing && cd native_fuzzing
sed 's/go 1.16/go 1.18/g' -i $SRC/kubernetes/go.mod
printf "package main\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/utils\"\n" > register.go

gotip get github.com/AdamKorcz/go-118-fuzz-build/utils
gotip mod tidy
gotip mod vendor

# Delete broken fuzzer
find $SRC/kubernetes/vendor/github.com/cilium/ebpf/internal/btf -name "fuzz.go" -exec rm -rf {} \;

echo "compiling..."
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseQuantity fuzz_parse_quantity
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzMeta1ParseToLabelSelector fuzz_meta1_parse_to_label_selector
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseSelector fuzz_parse_selector
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzLabelsParse fuzz_labels_parse
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseGroupVersion fuzz_parse_group_version
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseResourceArg fuzz_parse_resource_arg
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseVersion fuzz_parse_version
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParsePrivateKeyPEM fuzz_parse_private_pem
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParsePublicKeysPEM fuzz_parse_public_keys_pem
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseHostPort fuzz_parse_host_port
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzUrlsMatch fuzz_urls_match
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseCSR fuzz_parse_csr
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseEnv fuzz_parse_env
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseQOSReserve fuzz_parse_qos_reserve
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseCPUSet fuzz_parse_cpu_set
compile_native_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzParseImageName fuzz_parse_image_name

sed 's/go 1.18/go 1.16/g' -i $SRC/kubernetes/go.mod


cd $SRC/kubernetes/test/fuzz/fuzzing

rm $KUBE_FUZZERS/parser_fuzzer.go
cp $SRC/cncf-fuzzing/projects/kubernetes/*.go \
   $SRC/kubernetes/test/fuzz/fuzzing/
rm native_go_parser_fuzzers_test.go

# disable this fuzzer for now
#compile_go_fuzzer k8s.io/kubernetes/pkg/kubelet/server FuzzRequest fuzz_request

go mod tidy && go mod vendor
# Delete broken fuzzer
find $SRC/kubernetes/vendor/github.com/cilium/ebpf/internal/btf -name "fuzz.go" -exec rm -rf {} \;

# Add the swagger.json content to the kubectl fuzzer
apt-get update && apt-get install -y wget
wget https://raw.githubusercontent.com/kubernetes/kubernetes/master/staging/src/k8s.io/kubectl/testdata/openapi/swagger.json
sed -i 's/`//g' swagger.json
echo -e "\nvar swaggerjson = \`">>kubectl_fuzzer.go
cat swagger.json>>kubectl_fuzzer.go
echo -e "\`">>kubectl_fuzzer.go
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzCreateElement fuzz_create_element


compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzApiMarshaling fuzz_api_marshaling
compile_go_fuzzer k8s.io/kubernetes/pkg/kubelet/kuberuntime FuzzKubeRuntime fuzz_kube_runtime
compile_go_fuzzer k8s.io/kubernetes/pkg/kubelet FuzzSyncPod fuzz_sync_pod
compile_go_fuzzer k8s.io/kubernetes/pkg/kubelet FuzzStrategicMergePatch fuzz_strategic_merge_patch
compile_go_fuzzer k8s.io/kubernetes/pkg/kubelet FuzzconvertToAPIContainerStatuses fuzz_convert_to_api_container_statuses
compile_go_fuzzer k8s.io/kubernetes/pkg/kubelet FuzzHandlePodCleanups fuzz_handle_pod_cleanups
compile_go_fuzzer k8s.io/kubernetes/pkg/kubelet FuzzMakeEnvironmentVariables fuzz_make_environment_variables

compile_go_fuzzer k8s.io/kubernetes/pkg/controller/deployment/util FuzzEntireDeploymentUtil fuzz_entire_deployment_util

compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzDeepCopy fuzz_deep_copy
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzAesRoundtrip fuzz_aes_roundtrip
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzLoadPolicyFromBytes fuzz_load_policy_from_bytes
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing RegistryFuzzer registry_fuzzer
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzUnrecognized fuzz_unrecognized
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzRoundTripSpecificKind fuzz_roundtrip_specific_kind
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzControllerRoundtrip fuzz_controller_roundtrip
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzKubeletSchemeRoundtrip fuzz_kubelet_scheme_roundtrip
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzProxySchemeRoundtrip fuzz_proxy_scheme_roundtrip
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzRoundTripType fuzz_rountrip_type
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzDecodeRemoteConfigSource fuzz_decode_remote_config_source
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzReadLogs fuzz_read_logs
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzRoundtrip fuzz_roundtrip
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzSetDefaults_KubeSchedulerConfiguration fuzz_set_defaults_kube_scheduler_configuration
compile_go_fuzzer k8s.io/kubernetes/test/fuzz/fuzzing FuzzAllValidation fuzz_all_validation
cd $SRC/kubernetes
