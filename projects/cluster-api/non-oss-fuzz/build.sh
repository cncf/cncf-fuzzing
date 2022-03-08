# Setup CRDs for the controller fuzzers
cd $SRC/cncf-fuzzing/projects/cluster-api/crd-creation
go mod init create-fuzz-env
go mod tidy
go run main.go

cd $SRC/cluster-api
sed -i 's/root := path.Join(path.Dir(filename), "..", "..", "..")/root := "."/g' $SRC/cluster-api/internal/test/envtest/environment.go
sed -i '120 a code := 1' $SRC/cluster-api/internal/test/envtest/environment.go
sed -i 's/code := input.M.Run()/return 1/g' $SRC/cluster-api/internal/test/envtest/environment.go
sed -i 's/"path"/\/\/"path"/g' $SRC/cluster-api/internal/test/envtest/environment.go
sed -i 's/_, filename, _, _/\/\/_, filename, _, _/g' $SRC/cluster-api/internal/test/envtest/environment.go
#sed -i 's/err = kerrors.NewAggregate([]error{err, env.Stop()})/\/\/err = kerrors.NewAggregate([]error{err, env.Stop()})/g' $SRC/cluster-api/internal/test/envtest/environment.go

sed -i 's/root := path.Join(path.Dir(filename), "..", "..", "..")/root := "."/g' $SRC/cluster-api/internal/test/envtest/webhooks.go
sed -i 's/"path"/\/\/"path"/g' $SRC/cluster-api/internal/test/envtest/webhooks.go
sed -i 's/_, filename, _, _/\/\/_, filename, _, _/g' $SRC/cluster-api/internal/test/envtest/webhooks.go
sed -i 's/goruntime "runtime"/\/\/goruntime "runtime"/g' $SRC/cluster-api/internal/test/envtest/webhooks.go


cp $SRC/cncf-fuzzing/projects/cluster-api/cluster_controller_fuzzer.go \
   $SRC/cluster-api/internal/controllers/cluster/
compile_go_fuzzer sigs.k8s.io/cluster-api/internal/controllers/cluster FuzzClusterController fuzz_cluster_controller
exit 0