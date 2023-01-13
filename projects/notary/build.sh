sed 's/go 1.17/go 1.19/g' -i $SRC/notary/go.mod

export CNCFFuzz="${SRC}/cncf-fuzzing/projects/notary"

cp $CNCFFuzz/fuzz_trustmanager_test.go $SRC/notary/trustmanager/

printf "package trustmanager\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/notary/trustmanager/registerfuzzdep.go
go mod tidy && go mod vendor
compile_go_fuzzer github.com/theupdateframework/notary/cryptoservice/fuzz Fuzz fuzz

mv $SRC/notary/trustmanager/keys_test.go $SRC/notary/trustmanager/keys_test_fuzz.go
mv $SRC/notary/trustmanager/keystore_test.go $SRC/notary/trustmanager/keystore_test_fuzz.go
compile_native_go_fuzzer github.com/theupdateframework/notary/trustmanager FuzzImportKeysSimple FuzzImportKeysSimple
compile_native_go_fuzzer github.com/theupdateframework/notary/trustmanager FuzzImportKeysStructured FuzzImportKeysStructured

mv $SRC/cncf-fuzzing/projects/notary/fuzz_handlers.go $SRC/notary/server/handlers/
compile_native_go_fuzzer github.com/theupdateframework/notary/server/handlers FuzzAtomicUpdateHandler FuzzAtomicUpdateHandler

cd $SRC/notation-go
mv "${SRC}/cncf-fuzzing/projects/notary/fuzz_verification.go" $SRC/notation-go/verifier/
printf "package verifier\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > verifier/registerfuzzdep.go
go mod tidy
compile_native_go_fuzzer github.com/notaryproject/notation-go/verifier FuzzVerify FuzzVerify
