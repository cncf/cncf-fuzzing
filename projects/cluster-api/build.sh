set -o nounset
set -o pipefail
set -o errexit
set -x

go get github.com/AdaLogics/go-fuzz-headers@latest
cd "$SRC"
git clone --depth=1 https://github.com/AdamKorcz/go-118-fuzz-build --branch=include-all-test-files
cd go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/
cd $SRC/cluster-api
# Controllers
##########################################################
cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_cluster_controller.go \
   $SRC/cluster-api/internal/controllers/cluster/fuzz_test.go

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_clusterclass_controller.go \
   $SRC/cluster-api/internal/controllers/clusterclass/fuzz_test.go

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_machine_controller.go \
   $SRC/cluster-api/internal/controllers/machine/fuzz_test.go

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_machinedeployment_controller.go \
   $SRC/cluster-api/internal/controllers/machinedeployment/fuzz_test.go

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_machinehealthcheck_controller.go \
   $SRC/cluster-api/internal/controllers/machinehealthcheck/fuzz_test.go

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_machineset_controller.go \
   $SRC/cluster-api/internal/controllers/machineset/fuzz_test.go

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_util_container.go \
   $SRC/cluster-api/util/container/fuzz_test.go
########################################################
printf "package util\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > util/register.go
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build="$SRC"/go-118-fuzz-build

go mod tidy
compile_native_go_fuzzer sigs.k8s.io/cluster-api/util/container FuzzModifyImageRepository fuzz_modify_image_repository
compile_native_go_fuzzer sigs.k8s.io/cluster-api/util/container FuzzModifyImageTag fuzz_modify_image_tag
compile_native_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/cluster FuzzClusterReconcile fuzz_cluster_controller
compile_native_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/clusterclass FuzzClusterClassReconcile fuzz_clusterclass_controller
compile_native_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/machine FuzzMachineReconcile fuzz_machine_controller
compile_native_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/machinedeployment FuzzMachineDeploymentReconcile fuzz_machinedepoyment_controller
compile_native_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/machinehealthcheck FuzzMachineHealthCheckReconcile fuzz_machinehealthcheck_controller
compile_native_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/machineset FuzzMachinesetReconcile fuzz_machineset_controller

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_kubeadm_internal.go \
   $SRC/cluster-api/controlplane/kubeadm/internal/fuzz_test.go
cd $SRC/cluster-api/controlplane/kubeadm/internal
compile_native_go_fuzzer . FuzzMatchesMachineSpec fuzz_matches_machine_spec
cd $SRC/cluster-api

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_internal_kubeadm_controller.go \
   $SRC/cluster-api/controlplane/kubeadm/internal/controllers/fuzz_test.go
cd $SRC/cluster-api/controlplane/kubeadm/internal/controllers
compile_native_go_fuzzer . FuzzKubeadmControlPlaneReconciler fuzz_kubeadm_controlplane_reconciler
cd $SRC/cluster-api

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_patch.go \
   $SRC/cluster-api/util/patch/fuzz_test.go
compile_native_go_fuzzer sigs.k8s.io/cluster-api/util/patch FuzzPatch fuzz_patch

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_conditions.go \
   $SRC/cluster-api/util/conditions/fuzz_test.go
compile_native_go_fuzzer sigs.k8s.io/cluster-api/util/conditions FuzzPatchApply fuzz_patch_apply

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_topology_cluster_reconciler.go \
   $SRC/cluster-api/internal/controllers/topology/cluster/fuzz_test.go
compile_native_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/topology/cluster FuzzClusterReconcile fuzz_cluster_reconcile

mkdir $SRC/cluster-api/fuzz

cp $SRC/cncf-fuzzing/projects/cluster-api/yaml_fuzzer.go \
	$SRC/cluster-api/util/yaml/fuzz_test.go

compile_native_go_fuzzer sigs.k8s.io/cluster-api/util/yaml FuzzYamlParse fuzz_yaml_parser

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_bootstrap_kubeadm.go \
   $SRC/cluster-api/bootstrap/kubeadm/types/fuzz_test.go

compile_native_go_fuzzer sigs.k8s.io/cluster-api/bootstrap/kubeadm/types FuzzKubeadmTypesMarshalling fuzz_kubeadm_types_marshalling
compile_native_go_fuzzer sigs.k8s.io/cluster-api/bootstrap/kubeadm/types FuzzUnmarshalClusterConfiguration fuzz_unmarshal_cluster_configuration
compile_native_go_fuzzer sigs.k8s.io/cluster-api/bootstrap/kubeadm/types FuzzUnmarshalClusterStatus fuzz_unmarshal_cluster_status

cp $SRC/cncf-fuzzing/projects/cluster-api/fuzz_v1beta1_machine_webhook.go \
	$SRC/cluster-api/internal/webhooks/fuzz_test.go
compile_native_go_fuzzer sigs.k8s.io/cluster-api/internal/webhooks FuzzWebhookValidation fuzz_webhook_validation
