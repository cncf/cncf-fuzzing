
export CNCFPATH="${SRC}/"cncf-fuzzing/projects/distribution
export DISTRIBUTION="github.com/distribution/distribution/v3"
export REGISTRYPATH="${DISTRIBUTION}/registry"

mv $CNCFPATH/inmemory_fuzzer.go $SRC/distribution/registry/storage/driver/inmemory/

mv $CNCFPATH/reference_fuzzer.go $SRC/distribution/reference/

mv $CNCFPATH/api_v2_fuzzer.go $SRC/distribution/registry/api/v2/

mv $CNCFPATH/registry_fuzzer.go $SRC/distribution/registry/
mv $SRC/distribution/registry/registry_test.go \
   $SRC/distribution/registry/registry_test_fuzz.go

mv $CNCFPATH/client_fuzzer.go $SRC/distribution/registry/client/
mv $SRC/distribution/registry/client/repository_test.go \
   $SRC/distribution/registry/client/repository_test_fuzz.go

mv $CNCFPATH/storage_fuzzer.go $SRC/distribution/registry/storage/
mv $SRC/distribution/registry/storage/garbagecollect_test.go \
   $SRC/distribution/registry/storage/garbagecollect_test_fuzz.go

mv $CNCFPATH/swift_fuzzer.go $SRC/distribution/registry/storage/driver/swift/

mv $CNCFPATH/s3_aws_fuzzer.go $SRC/distribution/registry/storage/driver/s3-aws/

mv $CNCFPATH/ocischema_fuzzer.go $SRC/distribution/manifest/ocischema/

go mod tidy && go mod vendor
compile_go_fuzzer $DISTRIBUTION/reference FuzzParseNormalizedNamed fuzz_parsed_normalized_named
compile_go_fuzzer $DISTRIBUTION/manifest/ocischema FuzzManifestBuilder fuzz_manifest_builder

compile_go_fuzzer $REGISTRYPATH FuzzRegistry1 fuzz_registry1
compile_go_fuzzer $REGISTRYPATH FuzzRegistry2 fuzz_registry2
compile_go_fuzzer $REGISTRYPATH/api/v2/ FuzzParseForwardedHeader fuzz_parse_forwarded_header
compile_go_fuzzer $REGISTRYPATH/client FuzzBlobServeBlob fuzz_blob_serve_blob
compile_go_fuzzer $REGISTRYPATH/storage FuzzSchema2ManifestHandler fuzz_schema2_manifest_handler
compile_go_fuzzer $REGISTRYPATH/storage FuzzBlob fuzz_blob
compile_go_fuzzer $REGISTRYPATH/storage FuzzFR fuzz_fr
compile_go_fuzzer $REGISTRYPATH/storage/driver/inmemory FuzzInmemoryDriver fuzz_inmemory_driver
compile_go_fuzzer $REGISTRYPATH/storage/driver/s3-aws FuzzS3Driver fuzz_s3_driver
compile_go_fuzzer $REGISTRYPATH/storage/driver/swift FuzzSwift fuzz_swift
