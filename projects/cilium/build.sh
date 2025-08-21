# install Go 1.19
cd $SRC/cilium

export CILIUM=$SRC/cncf-fuzzing/projects/cilium

cd $SRC/proxy
mv $CILIUM/OnData_fuzzer.go $SRC/proxy/proxylib/cassandra/
mv $SRC/proxy/proxylib/cassandra/cassandraparser_test.go $SRC/proxy/proxylib/cassandra/cassandraparser_test_fuzz.go
go mod tidy && go mod vendor
compile_go_fuzzer github.com/cilium/proxy/proxylib/cassandra FuzzMultipleParsers fuzz_multiple_parsers
cd -
