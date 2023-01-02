
mv $SRC/cncf-fuzzing/fuzz_handlers.go $SRC/notary/server/handlers/
compile_native_go_fuzzer github.com/theupdateframework/notary/server/handlers FuzzAtomicUpdateHandler FuzzAtomicUpdateHandler

