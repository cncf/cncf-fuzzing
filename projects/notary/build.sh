#!/bin/bash -eu
# Copyright 2023 the cncf-fuzzing authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

set -o nounset
set -o pipefail
set -o errexit
set -x

sed 's/go 1.17/go 1.19/g' -i $SRC/notary/go.mod

export CNCFFuzz="${SRC}/cncf-fuzzing/projects/notary"

cp $CNCFFuzz/fuzz_trustmanager_test.go $SRC/notary/trustmanager/
cp $CNCFFuzz/fuzz_tuf_utils.go $SRC/notary/tuf/utils/

printf "package trustmanager\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/notary/trustmanager/registerfuzzdep.go
go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
go mod tidy && go mod vendor
compile_go_fuzzer github.com/theupdateframework/notary/cryptoservice/fuzz Fuzz fuzz

mv $SRC/notary/trustmanager/keys_test.go $SRC/notary/trustmanager/keys_test_fuzz.go
mv $SRC/notary/trustmanager/keystore_test.go $SRC/notary/trustmanager/keystore_test_fuzz.go
compile_native_go_fuzzer github.com/theupdateframework/notary/trustmanager FuzzImportKeysSimple FuzzImportKeysSimple
compile_native_go_fuzzer github.com/theupdateframework/notary/trustmanager FuzzImportKeysStructured FuzzImportKeysStructured
compile_native_go_fuzzer github.com/theupdateframework/notary/tuf/utils FuzzParsePEMPrivateKey FuzzParsePEMPrivateKey

mv $SRC/cncf-fuzzing/projects/notary/fuzz_handlers.go $SRC/notary/server/handlers/
compile_native_go_fuzzer github.com/theupdateframework/notary/server/handlers FuzzAtomicUpdateHandler FuzzAtomicUpdateHandler
compile_native_go_fuzzer github.com/theupdateframework/notary/server/handlers FuzzAtomicUpdateHandlerMultipart FuzzAtomicUpdateHandlerMultipart
compile_native_go_fuzzer github.com/theupdateframework/notary/server/handlers FuzzGetKeyHandler FuzzGetKeyHandler
compile_native_go_fuzzer github.com/theupdateframework/notary/server/handlers FuzzChangefeed FuzzChangefeed
compile_native_go_fuzzer github.com/theupdateframework/notary/server/handlers FuzzRotateKeyHandler FuzzRotateKeyHandler
compile_native_go_fuzzer github.com/theupdateframework/notary/server/handlers FuzzDeleteHandler FuzzDeleteHandler


mv $SRC/cncf-fuzzing/projects/notary/fuzz_keydbstore.go $SRC/notary/signer/keydbstore/
mv $SRC/notary/signer/keydbstore/keydbstore_test.go $SRC/notary/signer/keydbstore/keydbstore_test_fuzz.go
mv $SRC/notary/signer/keydbstore/cachedcryptoservice_test.go $SRC/notary/signer/keydbstore/cachedcryptoservice_test_fuzz.go
compile_native_go_fuzzer github.com/theupdateframework/notary/signer/keydbstore FuzzKeyDBStore FuzzKeyDBStore

mv $SRC/cncf-fuzzing/projects/notary/fuzz_server_storage.go $SRC/notary/server/storage/
mv $SRC/notary/server/storage/storage_test.go $SRC/notary/server/storage/storage_test_fuzz.go
compile_native_go_fuzzer github.com/theupdateframework/notary/server/storage FuzzServerStorageSQL FuzzServerStorage
compile_native_go_fuzzer github.com/theupdateframework/notary/server/storage FuzzServerStorageMemStorage FuzzServerStorageMemStorage
compile_native_go_fuzzer github.com/theupdateframework/notary/server/storage FuzzServerStorageTufStorage FuzzServerStorageTufStorage



cd $SRC/notation-go
mv "${SRC}/cncf-fuzzing/projects/notary/fuzz_verification.go" $SRC/notation-go/verifier/
mv "${SRC}/cncf-fuzzing/projects/notary/fuzz_pkix_test.go" $SRC/notation-go/internal/pkix/
mv "${SRC}/cncf-fuzzing/projects/notary/fuzz_notation_artifactref_parsing.go" $SRC/notation-go/
mv "${SRC}/cncf-fuzzing/projects/notary/fuzz_trustpolicy.go" $SRC/notation-go/verifier/trustpolicy/
printf "package verifier\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > verifier/registerfuzzdep.go
go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
go mod tidy
compile_native_go_fuzzer github.com/notaryproject/notation-go/verifier FuzzVerify FuzzVerify
compile_native_go_fuzzer github.com/notaryproject/notation-go/verifier/trustpolicy FuzzDocumentValidate FuzzDocumentValidate
compile_native_go_fuzzer github.com/notaryproject/notation-go FuzzArtifactReferenceParsing FuzzArtifactReferenceParsing
compile_native_go_fuzzer github.com/notaryproject/notation-go/internal/pkix FuzzParseDistinguishedName FuzzParseDistinguishedName


cd $SRC
git clone --depth=1 https://github.com/notaryproject/notation-core-go
cd notation-core-go
printf "package cose\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > signature/cose/registerfuzzdep.go
cp $CNCFFuzz/fuzz_cose.go $SRC/notation-core-go/signature/cose/
cp $CNCFFuzz/fuzz_jws.go $SRC/notation-core-go/signature/jws/
go mod edit -replace github.com/AdaLogics/go-fuzz-headers=github.com/AdamKorcz/go-fuzz-headers-1@1f10f66a31bf0e5cc26a2f4a74bd3be5f6463b67
go mod tidy
compile_native_go_fuzzer github.com/notaryproject/notation-core-go/signature/cose FuzzSignatureCose FuzzSignatureCose
compile_native_go_fuzzer github.com/notaryproject/notation-core-go/signature/jws FuzzSignatureJws FuzzSignatureJws
