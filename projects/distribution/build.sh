#!/bin/bash -eu
set -o nounset
set -o pipefail
set -o errexit
set -x

apt-get update && apt-get install -y wget
cd $SRC
wget https://go.dev/dl/go1.18.2.linux-amd64.tar.gz

mkdir temp-go
rm -rf /root/.go/*
tar -C temp-go/ -xzf go1.18.2.linux-amd64.tar.gz
mv temp-go/go/* /root/.go/
cd $SRC/distribution



export CNCFPATH="${SRC}/"cncf-fuzzing/projects/distribution
export DISTRIBUTION="github.com/distribution/distribution/v3"
export REGISTRYPATH="${DISTRIBUTION}/registry"

mv $CNCFPATH/inmemory_fuzzer.go $SRC/distribution/registry/storage/driver/inmemory/

mv $CNCFPATH/registry_fuzzer.go $SRC/distribution/registry/
mv $SRC/distribution/registry/registry_test.go \
   $SRC/distribution/registry/registry_test_fuzz.go

mv $CNCFPATH/client_fuzzer.go $SRC/distribution/registry/client/
mv $SRC/distribution/registry/client/repository_test.go \
   $SRC/distribution/registry/client/repository_test_fuzz.go

mv $CNCFPATH/storage_fuzzer.go $SRC/distribution/registry/storage/
mv $SRC/distribution/registry/storage/garbagecollect_test.go \
   $SRC/distribution/registry/storage/garbagecollect_test_fuzz.go


mv $CNCFPATH/access_controller_fuzzer.go $SRC/distribution/registry/auth/htpasswd/

mv $CNCFPATH/swift_fuzzer.go $SRC/distribution/registry/storage/driver/swift/

mv $CNCFPATH/s3_aws_fuzzer.go $SRC/distribution/registry/storage/driver/s3-aws/

mv $CNCFPATH/ocischema_fuzzer.go $SRC/distribution/manifest/ocischema/ 

mv $SRC/distribution/manifest/schema1/config_builder_test.go \
   $SRC/distribution/manifest/schema1/config_builder_test_fuzz.go
mv $CNCFPATH/schema1_fuzzer.go $SRC/distribution/manifest/schema1/

mv $CNCFPATH/authchallenge_fuzzer.go $SRC/distribution/registry/client/auth/challenge/
mv $CNCFPATH/token_fuzzer.go $SRC/distribution/registry/auth/token/
mv $CNCFPATH/set_fuzzer.go $SRC/distribution/digestset/
mv $CNCFPATH/reference_fuzzer2.go $SRC/distribution/reference/
mv $CNCFPATH/native_reference_fuzzer.go $SRC/distribution/reference/
mv $CNCFPATH/file_driver_fuzzer.go $SRC/distribution/registry/storage/driver/filesystem/
mv $CNCFPATH/app_fuzzer.go $SRC/distribution/registry/handlers/
mv $SRC/distribution/registry/handlers/api_test.go $SRC/distribution/registry/handlers/api_test_fuzz.go

mv $CNCFPATH/registry_proxy_fuzzer.go $SRC/distribution/registry/proxy/
cd $SRC/distribution/registry/proxy
mv proxymanifeststore_test.go proxymanifeststore_test_fuzz.go
mv proxyblobstore_test.go proxyblobstore_test_fuzz.go
mv proxytagservice_test.go proxytagservice_test_fuzz.go
cd -

mv $CNCFPATH/digestset_fuzzer.go $SRC/distribution/digestset/

mv $CNCFPATH/errcode_fuzzer.go $SRC/distribution/registry/api/errcode

# Replace upstream fuzzer with this updated version:
mv $CNCFPATH/parser_fuzzer.go $SRC/distribution/configuration/fuzz.go
# create seed files for this fuzzer:
zip $OUT/parser_fuzzer_seed_corpus.zip $CNCFPATH/corpus/parserFuzzer/*

rm -r ./vendor

# Used to build native fuzzers
gotip get github.com/AdamKorcz/go-118-fuzz-build/utils
gotip get github.com/AdaLogics/go-fuzz-headers
#compile_native_go_fuzzer $DISTRIBUTION/reference FuzzParseNormalizedNamedNative fuzz_parse_normalized_name_native
rm $SRC/distribution/reference/native_reference_fuzzer.go

go mod edit -dropreplace google.golang.org/grpc
go mod download && go mod tidy

$SRC/distribution/script/oss_fuzz_build.sh

compile_go_fuzzer $DISTRIBUTION/reference FuzzParseNormalizedNamed fuzz_parse_normalized_named
compile_go_fuzzer $DISTRIBUTION/reference FuzzWithNameAndWithTag fuzz_with_name_and_tag
compile_go_fuzzer $DISTRIBUTION/reference FuzzAllNormalizeApis fuzz_all_normalize_apis
compile_go_fuzzer $DISTRIBUTION/manifest/ocischema FuzzManifestBuilder fuzz_manifest_builder

compile_go_fuzzer $REGISTRYPATH/handlers FuzzApp fuzz_app
compile_go_fuzzer $REGISTRYPATH/api/errcode FuzzErrcode fuzz_errcode
compile_go_fuzzer $REGISTRYPATH/proxy FuzzProxyBlobstore fuzz_proxy_blobstore
compile_go_fuzzer $REGISTRYPATH/proxy FuzzProxyManifestStore fuzz_proxy_manifest_store
compile_go_fuzzer $REGISTRYPATH/auth/htpasswd FuzzAccessController fuzz_access_controller
compile_go_fuzzer $DISTRIBUTION/digestset FuzzDigestSet fuzz_digestset
compile_go_fuzzer $DISTRIBUTION/manifest/schema1 FuzzSchema1Build fuzz_schema1_build
compile_go_fuzzer $DISTRIBUTION/manifest/schema1 FuzzSchema1Verify fuzz_schema1_verify
compile_go_fuzzer $DISTRIBUTION/digestset FuzzSet fuzz_set
compile_go_fuzzer $REGISTRYPATH/auth/token FuzzToken fuzz_token
compile_go_fuzzer $REGISTRYPATH/auth/token FuzzToken2 fuzz_token2
compile_go_fuzzer $REGISTRYPATH/client/auth/challenge FuzzParseValueAndParams fuzz_parse_value_and_params
compile_go_fuzzer $REGISTRYPATH FuzzRegistry1 fuzz_registry1
compile_go_fuzzer $REGISTRYPATH FuzzRegistry2 fuzz_registry2
compile_go_fuzzer $REGISTRYPATH/client FuzzBlobServeBlob fuzz_blob_serve_blob
compile_go_fuzzer $REGISTRYPATH/client FuzzRegistryClient fuzz_registry_client
compile_go_fuzzer $REGISTRYPATH/storage FuzzSchema2ManifestHandler fuzz_schema2_manifest_handler
compile_go_fuzzer $REGISTRYPATH/storage FuzzBlob fuzz_blob
compile_go_fuzzer $REGISTRYPATH/storage FuzzMarkAndSweep fuzz_mark_and_sweep
compile_go_fuzzer $REGISTRYPATH/storage FuzzFR fuzz_fr
compile_go_fuzzer $REGISTRYPATH/storage/driver/inmemory FuzzInmemoryDriver fuzz_inmemory_driver
compile_go_fuzzer $REGISTRYPATH/storage/driver/s3-aws FuzzS3Driver fuzz_s3_driver
compile_go_fuzzer $REGISTRYPATH/storage/driver/swift FuzzSwift fuzz_swift
compile_go_fuzzer $REGISTRYPATH/storage/driver/filesystem FuzzFilesystemDriver fuzz_filesystem_driver
