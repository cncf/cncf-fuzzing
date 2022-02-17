cp $SRC/cncf-fuzzing/projects/cluster-api/yaml_fuzzer.go \
	$SRC/cluster-api/util/yaml/

compile_go_fuzzer sigs.k8s.io/cluster-api/util/yaml FuzzYamlParse fuzz_yaml_parser

cp $SRC/cncf-fuzzing/projects/cluster-api/bootstrap_kubeadm_fuzzer.go \
   $SRC/cluster-api/bootstrap/kubeadm/types/

compile_go_fuzzer sigs.k8s.io/cluster-api/bootstrap/kubeadm/types FuzzKubeadmTypesMarshalling fuzz_kubeadm_types_marshalling
compile_go_fuzzer sigs.k8s.io/cluster-api/bootstrap/kubeadm/types FuzzUnmarshalClusterConfiguration fuzz_unmarshal_cluster_configuration
compile_go_fuzzer sigs.k8s.io/cluster-api/bootstrap/kubeadm/types FuzzUnmarshalClusterStatus fuzz_unmarshal_cluster_status

