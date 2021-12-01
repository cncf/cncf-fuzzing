# Delete the "FORBIDDEN_DEPENDENCY" replacements
sed -i '/FORBIDDEN_DEPENDENCY/d' $SRC/etcd/server/go.mod
sed -i '/FORBIDDEN_DEPENDENCY/d' $SRC/etcd/raft/go.mod

# backend fuzzer
echo "building backend fuzzer"
cd $SRC/etcd/server/storage/backend/testing
mv $SRC/cncf-fuzzing/projects/etcd/backend_fuzzer.go ./
pwd
go get github.com/AdaLogics/go-fuzz-headers
go-fuzz -tags gofuzz -func FuzzBackend -o FuzzBackend.a .
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzBackend.a -lpthread -o $OUT/fuzz_backend

# grpc api fuzzer
mkdir $SRC/etcd/tests/fuzzing
mv $SRC/cncf-fuzzing/projects/etcd/v3_grpc_fuzzer.go $SRC/etcd/tests/fuzzing/
cd $SRC/etcd/tests/fuzzing
sed -i '219d' $SRC/etcd/tests/framework/integration/cluster.go
compile_go_fuzzer . FuzzGRPCApis fuzz_grpc_apis
cd -


# rafthttp fuzzer
mv $SRC/cncf-fuzzing/projects/etcd/raft_api_fuzzer.go $SRC/etcd/server/etcdserver/api/rafthttp/
mv $SRC/etcd/server/etcdserver/api/rafthttp/functional_test.go \
   $SRC/etcd/server/etcdserver/api/rafthttp/functional_test_fuzz.go

cd $SRC/etcd/server/etcdserver/api/rafthttp
go mod tidy

go-fuzz -tags gofuzz -func FuzzRaftHttpRequests -o FuzzRaftHttpRequests.a .
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzRaftHttpRequests.a -lpthread -o $OUT/fuzz_raft_http_requests

go-fuzz -tags gofuzz -func FuzzMessageEncodeDecode -o FuzzMessageEncodeDecode.a .
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzMessageEncodeDecode.a -lpthread -o $OUT/fuzz_message_encode_decode

# raft fuzzer
cd $SRC/etcd/raft
mv $SRC/cncf-fuzzing/projects/etcd/raft_fuzzer.go ./
go mod tidy
mv diff_test.go diff_test_fuzz.go
mv log_test.go log_test_fuzz.go
mv raft_test.go raft_test_fuzz.go

go-fuzz -tags gofuzz -func FuzzNetworkSend -o FuzzNetworkSend.a .
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzNetworkSend.a -lpthread -o $OUT/fuzz_network_send

go-fuzz -tags gofuzz -func FuzzStep -o FuzzStep.a .
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzStep.a -lpthread -o $OUT/fuzz_step

# v2auth fuzzer
cd $SRC/etcd/server/etcdserver/api/v2auth
mv $SRC/cncf-fuzzing/projects/etcd/v2auth_fuzzer.go ./
mv auth_test.go auth_test_fuzz.go

go-fuzz -tags gofuzz -func FuzzCreateOrUpdateUser -o FuzzCreateOrUpdateUser.a .
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzCreateOrUpdateUser.a -lpthread -o $OUT/fuzz_create_or_update_user