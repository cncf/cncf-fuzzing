# install Go 1.19
cd $SRC/cilium

export CILIUM=$SRC/cncf-fuzzing/projects/cilium

cp $CILIUM/matchpattern_fuzzer.go $SRC/cilium/pkg/fqdn/matchpattern/
cp $CILIUM/hubble_parser_fuzzer.go $SRC/cilium/pkg/hubble/parser/
cp $CILIUM/labels_fuzzer.go $SRC/cilium/pkg/k8s/slim/k8s/apis/labels/
mv $CILIUM/format_fuzzer.go $SRC/cilium/pkg/monitor/format
mv $CILIUM/labelsfilter_fuzzer.go $SRC/cilium/pkg/labelsfilter/
printf "package v2\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/cilium/pkg/k8s/apis/cilium.io/v2/registerfuzzdep.go
go mod tidy && go mod vendor

# Disable logging
sed -i 's/logrus\.InfoLevel/logrus.PanicLevel/g' $SRC/cilium/pkg/logging/logging.go

compile_native_go_fuzzer github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2 FuzzCiliumNetworkPolicyParse FuzzCiliumNetworkPolicyParse
compile_native_go_fuzzer github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2 FuzzCiliumClusterwideNetworkPolicyParse FuzzCiliumClusterwideNetworkPolicyParse

compile_native_go_fuzzer github.com/cilium/cilium/pkg/policy FuzzTest Fuzz_resolveEgressPolicy
compile_go_fuzzer github.com/cilium/cilium/pkg/labelsfilter FuzzLabelsfilterPkg fuzz_labelsfilter_pkg
compile_go_fuzzer github.com/cilium/cilium/pkg/monitor/format FuzzFormatEvent fuzz_FormatEvent
compile_go_fuzzer github.com/cilium/cilium/pkg/fqdn/matchpattern FuzzMatchpatternValidate fuzz_matchpattern_validate
compile_go_fuzzer github.com/cilium/cilium/pkg/fqdn/matchpattern FuzzMatchpatternValidateWithoutCache fuzz_matchpattern_validate_without_cache
compile_go_fuzzer github.com/cilium/cilium/pkg/hubble/parser FuzzParserDecode fuzz_parser_decode
compile_go_fuzzer github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels FuzzLabelsParse fuzz_labels_parse

rm $SRC/cilium/pkg/lock/lock_debug.go

ln -s $SRC/proxy $GOPATH/src/github.com/cilium/proxy
cd $SRC/proxy
mv $CILIUM/OnData_fuzzer.go $SRC/proxy/proxylib/cassandra/
mv $SRC/proxy/proxylib/cassandra/cassandraparser_test.go $SRC/proxy/proxylib/cassandra/cassandraparser_test_fuzz.go
go mod tidy && go mod vendor
compile_go_fuzzer github.com/cilium/proxy/proxylib/cassandra FuzzMultipleParsers fuzz_multiple_parsers
cd -
