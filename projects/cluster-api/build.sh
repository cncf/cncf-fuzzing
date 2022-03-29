set -o nounset
set -o pipefail
set -o errexit
set -x

go get github.com/AdaLogics/go-fuzz-headers@fe11a1f79e80cc365788a8d8c10e5a0315571dc5

# Controllers
##########################################################
cp $SRC/cncf-fuzzing/projects/cluster-api/cluster_controller_fuzzer.go \
   $SRC/cluster-api/internal/controllers/cluster/
compile_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/cluster FuzzClusterReconcile fuzz_cluster_controller

cp $SRC/cncf-fuzzing/projects/cluster-api/clusterclass_controller_fuzzer.go \
   $SRC/cluster-api/internal/controllers/clusterclass/
compile_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/clusterclass FuzzClusterClassReconcile fuzz_clusterclass_controller

cp $SRC/cncf-fuzzing/projects/cluster-api/machine_controller_fuzzer.go \
   $SRC/cluster-api/internal/controllers/machine/
compile_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/machine FuzzMachineReconcile fuzz_machine_controller

cp $SRC/cncf-fuzzing/projects/cluster-api/machinedeployment_controller_fuzzer.go \
   $SRC/cluster-api/internal/controllers/machinedeployment/
compile_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/machinedeployment FuzzMachineDeploymentReconcile fuzz_machinedepoyment_controller

cp $SRC/cncf-fuzzing/projects/cluster-api/machinehealthcheck_controller_fuzzer.go \
   $SRC/cluster-api/internal/controllers/machinehealthcheck/
compile_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/machinehealthcheck FuzzMachineHealthCheckReconcile fuzz_machinehealthcheck_controller

cp $SRC/cncf-fuzzing/projects/cluster-api/machineset_controller_fuzzer.go \
   $SRC/cluster-api/internal/controllers/machineset/
compile_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/machineset FuzzMachinesetReconcile fuzz_machineset_controller
########################################################


cp $SRC/cncf-fuzzing/projects/cluster-api/util_container_fuzzer.go \
   $SRC/cluster-api/util/container/
compile_go_fuzzer sigs.k8s.io/cluster-api/util/container FuzzModifyImageRepository fuzz_modify_image_repository
compile_go_fuzzer sigs.k8s.io/cluster-api/util/container FuzzModifyImageTag fuzz_modify_image_tag

cp $SRC/cncf-fuzzing/projects/cluster-api/kubeadm_internal_fuzzer.go \
   $SRC/cluster-api/controlplane/kubeadm/internal/
cd $SRC/cluster-api/controlplane/kubeadm/internal
compile_go_fuzzer . FuzzMatchesMachineSpec fuzz_matches_machine_spec
cd $SRC/cluster-api

cp $SRC/cncf-fuzzing/projects/cluster-api/internal_kubeadm_controller_fuzzer.go \
   $SRC/cluster-api/controlplane/kubeadm/internal/controllers/
mv $SRC/cluster-api/controlplane/kubeadm/internal/controllers/fakes_test.go \
   $SRC/cluster-api/controlplane/kubeadm/internal/controllers/fakes_test_fuzz.go
mv $SRC/cluster-api/controlplane/kubeadm/internal/controllers/controller_test.go \
   $SRC/cluster-api/controlplane/kubeadm/internal/controllers/controller_test_fuzz.go
rm $SRC/cluster-api/controlplane/kubeadm/internal/controllers/suite_test.go
cd $SRC/cluster-api/controlplane/kubeadm/internal/controllers
compile_go_fuzzer . FuzzKubeadmControlPlaneReconciler fuzz_kubeadm_controlplane_reconciler
cd $SRC/cluster-api

cp $SRC/cncf-fuzzing/projects/cluster-api/patch_fuzzer.go \
   $SRC/cluster-api/util/patch/
compile_go_fuzzer sigs.k8s.io/cluster-api/util/patch FuzzPatch fuzz_patch

cp $SRC/cncf-fuzzing/projects/cluster-api/conditions_fuzzer.go \
   $SRC/cluster-api/util/conditions/
compile_go_fuzzer sigs.k8s.io/cluster-api/util/conditions FuzzPatchApply fuzz_patch_apply

cp $SRC/cncf-fuzzing/projects/cluster-api/topology_cluster_reconciler_fuzzer.go \
   $SRC/cluster-api/internal/controllers/topology/cluster/
compile_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/topology/cluster FuzzClusterReconcile fuzz_cluster_reconcile

mkdir $SRC/cluster-api/fuzz
cp $SRC/cncf-fuzzing/projects/cluster-api/conversion_fuzzer2.go \
	$SRC/cluster-api/fuzz/
compile_go_fuzzer sigs.k8s.io/cluster-api/fuzz FuzzConversionOfAllTypes fuzz_conversion_of_all_types


cp $SRC/cncf-fuzzing/projects/cluster-api/yaml_fuzzer.go \
	$SRC/cluster-api/util/yaml/

compile_go_fuzzer sigs.k8s.io/cluster-api/util/yaml FuzzYamlParse fuzz_yaml_parser

cp $SRC/cncf-fuzzing/projects/cluster-api/bootstrap_kubeadm_fuzzer.go \
   $SRC/cluster-api/bootstrap/kubeadm/types/

compile_go_fuzzer sigs.k8s.io/cluster-api/bootstrap/kubeadm/types FuzzKubeadmTypesMarshalling fuzz_kubeadm_types_marshalling
compile_go_fuzzer sigs.k8s.io/cluster-api/bootstrap/kubeadm/types FuzzUnmarshalClusterConfiguration fuzz_unmarshal_cluster_configuration
compile_go_fuzzer sigs.k8s.io/cluster-api/bootstrap/kubeadm/types FuzzUnmarshalClusterStatus fuzz_unmarshal_cluster_status

cp $SRC/cncf-fuzzing/projects/cluster-api/conversion_fuzzer.go \
	$SRC/cluster-api/api/v1alpha3/
compile_go_fuzzer sigs.k8s.io/cluster-api/api/v1alpha3 FuzzV1alpha3Conversion fuzz_v1alpha3_conversion

cp $SRC/cncf-fuzzing/projects/cluster-api/v1beta1_machine_webhook_fuzzer.go \
	$SRC/cluster-api/api/v1beta1/
compile_go_fuzzer sigs.k8s.io/cluster-api/api/v1beta1 FuzzWebhookValidation fuzz_webhook_validation
