#!/bin/bash -eu
# Copyright 2025 CNCF-Fuzzing authors
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

cd /tmp
export GOROOT=/root/.go
wget https://go.dev/dl/go1.25.5.linux-amd64.tar.gz

mkdir temp-go
tar -C temp-go/ -xzf go1.25.5.linux-amd64.tar.gz

rm -r /root/.go
mkdir /root/.go/
mv temp-go/go/* /root/.go/
rm -rf temp-go


cd $SRC/go-118-fuzz-build
go build
mv go-118-fuzz-build $GOPATH/bin/go-118-fuzz-build_v2
pushd cmd/convertLibFuzzerTestcaseToStdLibGo
  go build . && mv convertLibFuzzerTestcaseToStdLibGo $GOPATH/bin/
popd
pushd cmd/addStdLibCorpusToFuzzer
  go build . && mv addStdLibCorpusToFuzzer $GOPATH/bin/
popd
cd $SRC/openfga

cp $SRC/cncf-fuzzing/projects/openfga/*.go $SRC/openfga/tests/

fuzz_targets1=(
 FuzzCheckWithExclusion
 FuzzCheckWithIntersection
 FuzzCheckWithComputedUserset
 FuzzCheckWithPublicAccess
 FuzzCheckWithMultipleRestrictions
 FuzzCheckWithConditions
 FuzzCheckWithParentChild
 FuzzCheck_AllModels
 FuzzWildcardTupleset
 FuzzUsersetFromClause
 FuzzRandomAPI
 FuzzPublicUsersetConfusion
 FuzzModelUpdateBypass
 FuzzListObjectsMemoryLeak
 FuzzExpand
 FuzzListUsers
 FuzzRead
 FuzzBatchCheck
 FuzzStorageBackends
)

PKG="github.com/openfga/openfga/tests"
for f in "${fuzz_targets1[@]}"; do
  compile_native_go_fuzzer_v2 "$PKG" "$f" "$f"
done

# Add seed corpus for FuzzRandomAPI with diverse authorization models
# Note: Using || true and manual copy to work around cross-device link error in addStdLibCorpusToFuzzer
addStdLibCorpusToFuzzer -fuzzer_name FuzzRandomAPI -dir $SRC/cncf-fuzzing/projects/openfga/FuzzRandomAPI_seeds || {
  # If tool fails due to cross-device link, manually copy the zip
  if [ -f /tmp/FuzzRandomAPI_seed_corpus.zip ]; then
    cp /tmp/FuzzRandomAPI_seed_corpus.zip $OUT/FuzzRandomAPI_seed_corpus.zip
    echo "Manually copied FuzzRandomAPI_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzListObjectsMemoryLeak with schema 1.1 and 1.2 models
addStdLibCorpusToFuzzer -fuzzer_name FuzzListObjectsMemoryLeak -dir $SRC/cncf-fuzzing/projects/openfga/FuzzListObjectsMemoryLeak_seeds || {
  if [ -f /tmp/FuzzListObjectsMemoryLeak_seed_corpus.zip ]; then
    cp /tmp/FuzzListObjectsMemoryLeak_seed_corpus.zip $OUT/FuzzListObjectsMemoryLeak_seed_corpus.zip
    echo "Manually copied FuzzListObjectsMemoryLeak_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzExpand with various relation patterns
addStdLibCorpusToFuzzer -fuzzer_name FuzzExpand -dir $SRC/cncf-fuzzing/projects/openfga/FuzzExpand_seeds || {
  if [ -f /tmp/FuzzExpand_seed_corpus.zip ]; then
    cp /tmp/FuzzExpand_seed_corpus.zip $OUT/FuzzExpand_seed_corpus.zip
    echo "Manually copied FuzzExpand_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzListUsers with filtering patterns
addStdLibCorpusToFuzzer -fuzzer_name FuzzListUsers -dir $SRC/cncf-fuzzing/projects/openfga/FuzzListUsers_seeds || {
  if [ -f /tmp/FuzzListUsers_seed_corpus.zip ]; then
    cp /tmp/FuzzListUsers_seed_corpus.zip $OUT/FuzzListUsers_seed_corpus.zip
    echo "Manually copied FuzzListUsers_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzRead with pagination and filtering
addStdLibCorpusToFuzzer -fuzzer_name FuzzRead -dir $SRC/cncf-fuzzing/projects/openfga/FuzzRead_seeds || {
  if [ -f /tmp/FuzzRead_seed_corpus.zip ]; then
    cp /tmp/FuzzRead_seed_corpus.zip $OUT/FuzzRead_seed_corpus.zip
    echo "Manually copied FuzzRead_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzBatchCheck with multiple check scenarios
addStdLibCorpusToFuzzer -fuzzer_name FuzzBatchCheck -dir $SRC/cncf-fuzzing/projects/openfga/FuzzBatchCheck_seeds || {
  if [ -f /tmp/FuzzBatchCheck_seed_corpus.zip ]; then
    cp /tmp/FuzzBatchCheck_seed_corpus.zip $OUT/FuzzBatchCheck_seed_corpus.zip
    echo "Manually copied FuzzBatchCheck_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzStorageBackends with SQL injection and encoding tests
addStdLibCorpusToFuzzer -fuzzer_name FuzzStorageBackends -dir $SRC/cncf-fuzzing/projects/openfga/FuzzStorageBackends_seeds || {
  if [ -f /tmp/FuzzStorageBackends_seed_corpus.zip ]; then
    cp /tmp/FuzzStorageBackends_seed_corpus.zip $OUT/FuzzStorageBackends_seed_corpus.zip
    echo "Manually copied FuzzStorageBackends_seed_corpus.zip to \$OUT"
  fi
}
