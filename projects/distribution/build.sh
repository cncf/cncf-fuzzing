#!/bin/bash -eu
set -o nounset
set -o pipefail
set -o errexit
set -x

cd "$SRC"
cd go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/

cd $SRC/distribution
printf "package registry\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > registry/fuzzing_register.go
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build="$SRC"/go-118-fuzz-build
go mod tidy

export CNCFPATH="${SRC}/"cncf-fuzzing/projects/distribution
export DISTRIBUTION="github.com/distribution/distribution/v3"
export REGISTRYPATH="${DISTRIBUTION}/registry"

mv $CNCFPATH/inmemory_fuzzer.go $SRC/distribution/registry/storage/driver/inmemory/fuzz_test.go
rm $SRC/distribution/registry/storage/driver/inmemory/driver_test.go

mv $CNCFPATH/registry_fuzzer.go $SRC/distribution/registry/fuzz_test.go

#mv $CNCFPATH/client_fuzzer.go $SRC/distribution/internal/client/

mv $CNCFPATH/storage_fuzzer.go $SRC/distribution/registry/storage/fuzz_test.go


#mv $CNCFPATH/access_controller_fuzzer.go $SRC/distribution/registry/auth/htpasswd/

mv $CNCFPATH/s3_aws_fuzzer.go $SRC/distribution/registry/storage/driver/s3-aws/fuzz_test.go
rm $SRC/distribution/registry/storage/driver/s3-aws/s3_test.go

mv $CNCFPATH/ocischema_fuzzer.go $SRC/distribution/manifest/ocischema/fuzz_test.go

mv $CNCFPATH/authchallenge_fuzzer.go $SRC/distribution/internal/client/auth/challenge/fuzz_test.go
mv $CNCFPATH/file_driver_fuzzer.go $SRC/distribution/registry/storage/driver/filesystem/fuzz_test.go
rm $SRC/distribution/registry/storage/driver/filesystem/driver_test.go
mv $CNCFPATH/app_fuzzer.go $SRC/distribution/registry/handlers/fuzz_test.go

#mv $CNCFPATH/registry_proxy_fuzzer.go $SRC/distribution/registry/proxy/

mv $CNCFPATH/errcode_fuzzer.go $SRC/distribution/registry/api/errcode/fuzz_test.go

# Replace upstream fuzzer with this updated version:
mv $CNCFPATH/parser_fuzzer.go $SRC/distribution/configuration/fuzz.go
# create seed files for this fuzzer:
zip $OUT/parser_fuzzer_seed_corpus.zip $CNCFPATH/corpus/parserFuzzer/*

rm -r ./vendor

# Used to build native fuzzers
go get github.com/AdaLogics/go-fuzz-headers

go mod edit -dropreplace google.golang.org/grpc
go mod download && go mod tidy

#compile_native_go_fuzzer $DISTRIBUTION/manifest/ocischema FuzzManifestBuilder fuzz_manifest_builder

compile_native_go_fuzzer $REGISTRYPATH/handlers FuzzApp fuzz_app
compile_native_go_fuzzer $REGISTRYPATH/api/errcode FuzzErrcode fuzz_errcode
#compile_native_go_fuzzer $REGISTRYPATH/proxy FuzzProxyBlobstore fuzz_proxy_blobstore
#compile_native_go_fuzzer $REGISTRYPATH/proxy FuzzProxyManifestStore fuzz_proxy_manifest_store
#compile_native_go_fuzzer $REGISTRYPATH/auth/htpasswd FuzzAccessController fuzz_access_controller
compile_native_go_fuzzer $DISTRIBUTION/internal/client/auth/challenge FuzzParseValueAndParams fuzz_parse_value_and_params
compile_native_go_fuzzer $REGISTRYPATH FuzzRegistry1 fuzz_registry1
compile_native_go_fuzzer $REGISTRYPATH FuzzRegistry2 fuzz_registry2
#compile_native_go_fuzzer $REGISTRYPATH/client FuzzBlobServeBlob fuzz_blob_serve_blob
#compile_native_go_fuzzer $REGISTRYPATH/client FuzzRegistryClient fuzz_registry_clientls $SRC/distribution/registry/storage
compile_native_go_fuzzer $REGISTRYPATH/storage FuzzSchema2ManifestHandler fuzz_schema2_manifest_handler
compile_native_go_fuzzer $REGISTRYPATH/storage FuzzBlob fuzz_blob
compile_native_go_fuzzer $REGISTRYPATH/storage FuzzMarkAndSweep fuzz_mark_and_sweep
compile_native_go_fuzzer $REGISTRYPATH/storage FuzzFR fuzz_fr
compile_native_go_fuzzer $REGISTRYPATH/storage/driver/inmemory FuzzInmemoryDriver fuzz_inmemory_driver
compile_native_go_fuzzer $REGISTRYPATH/storage/driver/s3-aws FuzzS3Driver fuzz_s3_driver
compile_native_go_fuzzer $REGISTRYPATH/storage/driver/filesystem FuzzFilesystemDriver fuzz_filesystem_driver
