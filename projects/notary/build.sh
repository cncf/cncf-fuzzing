
mv $SRC/cncf-fuzzing/projects/notary/fuzz_handlers.go $SRC/notary/server/handlers/
compile_native_go_fuzzer github.com/theupdateframework/notary/server/handlers FuzzAtomicUpdateHandler FuzzAtomicUpdateHandler

cd $SRC/notation-go
mv $SRC/cncf-fuzzing/projects/notary/fuzz_verification.go $SRC/notation-go/verifier/
printf "package verifier\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > verifier/registerfuzzdep.go
go mod tidy
compile_native_go_fuzzer github.com/notaryproject/notation-go/verifier FuzzVerify FuzzVerify
