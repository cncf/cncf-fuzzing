set -o nounset
set -o pipefail
set -o errexit
set -x

mv $SRC/cncf-fuzzing/projects/cubefs/fuzz_master.go $SRC/cubefs/master/

go mod tidy
go mod vendor
go get github.com/AdaLogics/go-fuzz-headers
source $SRC/cubefs/build/cgo_env.sh
compile_go_fuzzer github.com/cubefs/cubefs/master FuzzCreateVol fuzz_create_vol
compile_go_fuzzer github.com/cubefs/cubefs/master FuzzNewMetaNode fuzz_new_metanode

mv $SRC/cncf-fuzzing/projects/cubefs/fuzz_metanode.go $SRC/cubefs/metanode/
compile_go_fuzzer github.com/cubefs/cubefs/metanode FuzzNewInode fuzz_new_inode
compile_go_fuzzer github.com/cubefs/cubefs/metanode FuzzNewExtend fuzz_new_extend

mv $SRC/cncf-fuzzing/projects/cubefs/fuzz_datanode.go $SRC/cubefs/datanode/
compile_go_fuzzer github.com/cubefs/cubefs/datanode FuzzNewDisk fuzz_new_disk

mv $SRC/cncf-fuzzing/projects/cubefs/fuzz_client.go $SRC/cubefs/client/fs/
compile_go_fuzzer github.com/cubefs/cubefs/client/fs FuzzNewFile fuzz_new_file

mv $SRC/cncf-fuzzing/projects/cubefs/fuzz_sdk.go $SRC/cubefs/sdk/meta/
compile_go_fuzzer github.com/cubefs/cubefs/sdk/meta FuzzNewMeta fuzz_new_meta
