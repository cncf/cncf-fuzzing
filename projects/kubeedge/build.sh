set -o nounset
set -o pipefail
set -o errexit
set -x

cp $SRC/cncf-fuzzing/lane_fuzzer.go $SRC/kubeedge/staging/src/github.com/kubeedge/viaduct/pkg/lane/
cd $SRC/kubeedge/staging/src/github.com/kubeedge/viaduct
sed '94d' -i $SRC/kubeedge/staging/src/github.com/kubeedge/viaduct/pkg/translator/message.go
compile_go_fuzzer github.com/kubeedge/viaduct/pkg/lane FuzzLaneReadMessage fuzz_lane_read_message