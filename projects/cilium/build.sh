# install Go 1.19
cd $SRC/cilium

export CILIUM=$SRC/cncf-fuzzing/projects/cilium

cp $CILIUM/elf_fuzzer.go $SRC/cilium/pkg/elf/
cp $CILIUM/bpf_fuzzer.go $SRC/cilium/pkg/bpf/
cp $CILIUM/matchpattern_fuzzer.go $SRC/cilium/pkg/fqdn/matchpattern/
cp $CILIUM/hubble_parser_fuzzer.go $SRC/cilium/pkg/hubble/parser/
cp $CILIUM/labels_fuzzer.go $SRC/cilium/pkg/k8s/slim/k8s/apis/labels/
mv $CILIUM/format_fuzzer.go $SRC/cilium/pkg/monitor/format
mv $CILIUM/labelsfilter_fuzzer.go $SRC/cilium/pkg/labelsfilter/
mv $CILIUM/config_fuzzer.go $SRC/cilium/pkg/bgp/config/
printf "package v2\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/cilium/pkg/k8s/apis/cilium.io/v2/registerfuzzdep.go
go mod tidy && go mod vendor

# Disablo logging
sed -i 's/logrus\.InfoLevel/logrus.PanicLevel/g' $SRC/cilium/pkg/logging/logging.go

compile_native_go_fuzzer github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2 FuzzCiliumNetworkPolicyParse FuzzCiliumNetworkPolicyParse
compile_native_go_fuzzer github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2 FuzzCiliumClusterwideNetworkPolicyParse FuzzCiliumClusterwideNetworkPolicyParse

mv $SRC/cilium/pkg/policy/l4_test.go $SRC/cilium/pkg/policy/l4_test_fuzz.go

compile_native_go_fuzzer github.com/cilium/cilium/pkg/policy FuzzTest Fuzz_resolveEgressPolicy
compile_go_fuzzer github.com/cilium/cilium/pkg/labelsfilter FuzzLabelsfilterPkg fuzz_labelsfilter_pkg
compile_go_fuzzer github.com/cilium/cilium/pkg/monitor FuzzDecodeTraceNotify fuzz_DecodeTraceNotify
compile_go_fuzzer github.com/cilium/cilium/pkg/monitor/format FuzzFormatEvent fuzz_FormatEvent
compile_go_fuzzer github.com/cilium/cilium/pkg/monitor/payload FuzzPayloadEncodeDecode FuzzPayloadEncodeDecode
compile_go_fuzzer github.com/cilium/cilium/pkg/elf FuzzElfOpen fuzz_elf_open
compile_go_fuzzer github.com/cilium/cilium/pkg/elf FuzzElfWrite fuzz_elf_write
compile_go_fuzzer github.com/cilium/cilium/pkg/bpf FuzzBpf fuzz_bpf
compile_go_fuzzer github.com/cilium/cilium/pkg/fqdn/matchpattern FuzzMatchpatternValidate fuzz_matchpattern_validate
compile_go_fuzzer github.com/cilium/cilium/pkg/fqdn/matchpattern FuzzMatchpatternValidateWithoutCache fuzz_matchpattern_validate_without_cache
compile_go_fuzzer github.com/cilium/cilium/pkg/hubble/parser FuzzParserDecode fuzz_parser_decode
compile_go_fuzzer github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels FuzzLabelsParse fuzz_labels_parse
compile_go_fuzzer github.com/cilium/cilium/proxylib/cassandra FuzzMultipleParsers fuzz_multiple_parsers

rm $SRC/cilium/pkg/lock/lock_debug.go

mv $SRC/config_fuzzer.go $SRC/cilium/pkg/bgp/config/
compile_go_fuzzer github.com/cilium/cilium/pkg/bgp/config FuzzConfigParse fuzz_config_parse

mv $CILIUM/policy_fuzzer.go $SRC/cilium/pkg/policy/
compile_go_fuzzer github.com/cilium/cilium/pkg/policy FuzzNewVisibilityPolicy fuzz_NewVisibilityPolicy

mv $CILIUM/fuzz_config_parse.options $OUT/
