# Delete the "FORBIDDEN_DEPENDENCY" replacements
sed -i '/FORBIDDEN_DEPENDENCY/d' $SRC/etcd/server/go.mod
sed -i '/FORBIDDEN_DEPENDENCY/d' $SRC/etcd/raft/go.mod

# auth store fuzzer
echo "building auth fuzzer"
cd $SRC/etcd/server/auth
go get github.com/AdaLogics/go-fuzz-headers
mv $SRC/cncf-fuzzing/projects/etcd/store_fuzzer.go ./
mv store_mock_test.go store_mock_test_fuzz.go
mv store_test.go store_test_fuzz.go
mv jwt_test.go jwt_test_fuzz.go
compile_go_fuzzer go.etcd.io/etcd/server/v3/auth FuzzAuthStore fuzz_auth_store

# backend fuzzer
echo "building backend fuzzer"
cd $SRC/etcd/server/storage/backend/testing
mv $SRC/cncf-fuzzing/projects/etcd/backend_fuzzer.go ./
go get github.com/AdaLogics/go-fuzz-headers
compile_go_fuzzer go.etcd.io/etcd/server/v3/storage/backend/testing FuzzBackend fuzz_backend

# grpc api fuzzer
mkdir $SRC/etcd/tests/fuzzing
mv $SRC/cncf-fuzzing/projects/etcd/v3_grpc_fuzzer.go $SRC/etcd/tests/fuzzing/
cd $SRC/etcd/tests/fuzzing
sed -i '220d' $SRC/etcd/tests/framework/integration/cluster.go
compile_go_fuzzer . FuzzGRPCApis fuzz_grpc_apis
cd -


# rafthttp fuzzer
mv $SRC/cncf-fuzzing/projects/etcd/raft_api_fuzzer.go $SRC/etcd/server/etcdserver/api/rafthttp/
mv $SRC/etcd/server/etcdserver/api/rafthttp/functional_test.go \
   $SRC/etcd/server/etcdserver/api/rafthttp/functional_test_fuzz.go

cd $SRC/etcd/server/etcdserver/api/rafthttp
go mod tidy
compile_go_fuzzer go.etcd.io/etcd/server/v3/etcdserver/api/rafthttp FuzzRaftHttpRequests fuzz_raft_http_requests

compile_go_fuzzer go.etcd.io/etcd/server/v3/etcdserver/api/rafthttp FuzzMessageEncodeDecode fuzz_message_encode_decode

# raft fuzzer
cd $SRC/etcd/raft
mv $SRC/cncf-fuzzing/projects/etcd/raft_fuzzer.go ./
go mod tidy
mv diff_test.go diff_test_fuzz.go
mv log_test.go log_test_fuzz.go
mv raft_test.go raft_test_fuzz.go

compile_go_fuzzer go.etcd.io/etcd/raft/v3 FuzzNetworkSend fuzz_network_send

compile_go_fuzzer go.etcd.io/etcd/raft/v3 FuzzStep fuzz_step

# v2auth fuzzer
cd $SRC/etcd/server/etcdserver/api/v2auth
mv $SRC/cncf-fuzzing/projects/etcd/v2auth_fuzzer.go ./
mv auth_test.go auth_test_fuzz.go

compile_go_fuzzer go.etcd.io/etcd/server/v3/etcdserver/api/v2auth FuzzCreateOrUpdateUser FuzzCreateOrUpdateUser
