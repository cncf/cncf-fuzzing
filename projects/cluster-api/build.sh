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
