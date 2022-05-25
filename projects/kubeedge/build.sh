set -o nounset
set -o pipefail
set -o errexit
set -x

cp $SRC/cncf-fuzzing/projects/kubeedge/lane_fuzzer.go $SRC/kubeedge/staging/src/github.com/kubeedge/viaduct/pkg/lane/
cd $SRC/kubeedge/staging/src/github.com/kubeedge/viaduct
sed '94d' -i $SRC/kubeedge/staging/src/github.com/kubeedge/viaduct/pkg/translator/message.go
compile_go_fuzzer github.com/kubeedge/viaduct/pkg/lane FuzzLaneReadMessage fuzz_lane_read_message

cp $SRC/cncf-fuzzing/projects/kubeedge/dtmanager_fuzzer.go $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/
mv $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/twin_test.go $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/twint_test_fuzz.go
cd $SRC/kubeedge
go mod tidy && go mod vendor

# remove logs
sed 's/klog\./\/\/klog\./g' -i $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/twin.go
sed 's/\"k8s\.io\/klog\/v2"/\/\/\"k8s\.io\/klog\/v2\"/g' -i $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/twin.go

sed 's/klog\./\/\/klog\./g' -i $SRC/kubeedge/edge/pkg/devicetwin/dtcontext/dtcontext.go
sed 's/\"k8s\.io\/klog\/v2"/\/\/\"k8s\.io\/klog\/v2\"/g' -i $SRC/kubeedge/edge/pkg/devicetwin/dtcontext/dtcontext.go
compile_go_fuzzer github.com/kubeedge/kubeedge/edge/pkg/devicetwin/dtmanager FuzzdealTwinUpdate fuzz_deal_twin_update
compile_go_fuzzer github.com/kubeedge/kubeedge/edge/pkg/devicetwin/dtmanager FuzzdealTwinGet fuzz_deal_twin_get
