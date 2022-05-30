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

sed 's/klog\./\/\/klog\./g' -i $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/communicate.go
sed 's/\"k8s\.io\/klog\/v2"/\/\/\"k8s\.io\/klog\/v2\"/g' -i $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/communicate.go

sed 's/klog\./\/\/klog\./g' -i $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/membership.go
sed 's/\"k8s\.io\/klog\/v2"/\/\/\"k8s\.io\/klog\/v2\"/g' -i $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/membership.go

sed 's/klog\./\/\/klog\./g' -i $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/device.go
sed 's/\"k8s\.io\/klog\/v2"/\/\/\"k8s\.io\/klog\/v2\"/g' -i $SRC/kubeedge/edge/pkg/devicetwin/dtmanager/device.go

compile_go_fuzzer github.com/kubeedge/kubeedge/edge/pkg/devicetwin/dtmanager FuzzdealTwinActions fuzz_deal_twin_actions

cp $SRC/cncf-fuzzing/projects/kubeedge/udsserver_fuzzer.go $SRC/kubeedge/cloud/pkg/cloudhub/servers/udsserver/
compile_go_fuzzer github.com/kubeedge/kubeedge/cloud/pkg/cloudhub/servers/udsserver FuzzExtractMessage fuzz_ExtractMessage
cp $SRC/cncf-fuzzing/projects/kubeedge/csidriver_fuzzer.go $SRC/kubeedge/cloud/pkg/csidriver/
compile_go_fuzzer github.com/kubeedge/kubeedge/cloud/pkg/csidriver FuzzextractMessage fuzz_extract_message

cp $SRC/cncf-fuzzing/projects/kubeedge/metaserver_fuzzer.go $SRC/kubeedge/pkg/metaserver/
compile_go_fuzzer github.com/kubeedge/kubeedge/pkg/metaserver FuzzParseKey fuzz_parse_key

cp $SRC/cncf-fuzzing/projects/kubeedge/stream_fuzzer.go $SRC/kubeedge/pkg/stream/
compile_go_fuzzer github.com/kubeedge/kubeedge/pkg/stream FuzzReadMessageFromTunnel fuz_read_message_from_tunnel


cp $SRC/cncf-fuzzing/projects/kubeedge/cloudhub_messagehandler_fuzzer.go $SRC/kubeedge/cloud/pkg/cloudhub/handler/
compile_go_fuzzer github.com/kubeedge/kubeedge/cloud/pkg/cloudhub/handler FuzzVolumeRegExp fuzz_volume_regexp

cp $SRC/cncf-fuzzing/projects/kubeedge/mqtt_broker_fuzzer.go $SRC/kubeedge/edge/pkg/eventbus/mqtt/
go get github.com/256dpi/gomqtt/client
go mod tidy && go mod vendor
sed 's/topic\.NewTree/topic\.NewStandardTree/g' -i $SRC/kubeedge/edge/pkg/eventbus/mqtt/server.go
compile_go_fuzzer github.com/kubeedge/kubeedge/edge/pkg/eventbus/mqtt FuzzMqttPublish fuzz_mqtt_publish

cp $SRC/cncf-fuzzing/projects/kubeedge/router_fuzzer.go $SRC/kubeedge/cloud/pkg/router/utils
compile_go_fuzzer github.com/kubeedge/kubeedge/cloud/pkg/router/utils FuzzRuleContains fuzz_rule_contains

mv $SRC/cncf-fuzzing/projects/kubeedge/dictionaries/* $OUT/