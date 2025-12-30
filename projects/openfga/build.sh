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
  echo "compiling fuzzer: pkg: $PKG... f: $f... f: $f..."
  compile_native_go_fuzzer_v2 "$PKG" "$f" "$f"
done

# Helper function to check if a zip file has at least one file
is_valid_seed_corpus() {
  local zipfile="$1"
  if [ ! -f "$zipfile" ]; then
    return 1
  fi
  # Count files in zip (excluding directory entries)
  local file_count=$(unzip -l "$zipfile" 2>/dev/null | grep -v '/$' | tail -n +4 | head -n -2 | wc -l)
  [ "$file_count" -ge 1 ]
}

# Add seed corpus for FuzzRandomAPI with diverse authorization models
# Note: Using || true and manual copy to work around cross-device link error in addStdLibCorpusToFuzzer
addStdLibCorpusToFuzzer -fuzzer_name FuzzRandomAPI -dir $SRC/cncf-fuzzing/projects/openfga/FuzzRandomAPI_seeds || {
  # If tool fails due to cross-device link, manually copy the zip (only if non-empty)
  if is_valid_seed_corpus /tmp/FuzzRandomAPI_seed_corpus.zip; then
    cp /tmp/FuzzRandomAPI_seed_corpus.zip $OUT/FuzzRandomAPI_seed_corpus.zip
    echo "Manually copied FuzzRandomAPI_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzListObjectsMemoryLeak with schema 1.1 and 1.2 models
addStdLibCorpusToFuzzer -fuzzer_name FuzzListObjectsMemoryLeak -dir $SRC/cncf-fuzzing/projects/openfga/seed_corpus/FuzzListObjectsMemoryLeak || {
  if is_valid_seed_corpus /tmp/FuzzListObjectsMemoryLeak_seed_corpus.zip; then
    cp /tmp/FuzzListObjectsMemoryLeak_seed_corpus.zip $OUT/FuzzListObjectsMemoryLeak_seed_corpus.zip
    echo "Manually copied FuzzListObjectsMemoryLeak_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzExpand with various relation patterns
addStdLibCorpusToFuzzer -fuzzer_name FuzzExpand -dir $SRC/cncf-fuzzing/projects/openfga/seed_corpus/FuzzExpand || {
  if is_valid_seed_corpus /tmp/FuzzExpand_seed_corpus.zip; then
    cp /tmp/FuzzExpand_seed_corpus.zip $OUT/FuzzExpand_seed_corpus.zip
    echo "Manually copied FuzzExpand_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzListUsers with filtering patterns
addStdLibCorpusToFuzzer -fuzzer_name FuzzListUsers -dir $SRC/cncf-fuzzing/projects/openfga/FuzzListUsers_seeds || {
  if is_valid_seed_corpus /tmp/FuzzListUsers_seed_corpus.zip; then
    cp /tmp/FuzzListUsers_seed_corpus.zip $OUT/FuzzListUsers_seed_corpus.zip
    echo "Manually copied FuzzListUsers_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzRead with pagination and filtering
addStdLibCorpusToFuzzer -fuzzer_name FuzzRead -dir $SRC/cncf-fuzzing/projects/openfga/seed_corpus/FuzzRead || {
  if is_valid_seed_corpus /tmp/FuzzRead_seed_corpus.zip; then
    cp /tmp/FuzzRead_seed_corpus.zip $OUT/FuzzRead_seed_corpus.zip
    echo "Manually copied FuzzRead_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzBatchCheck with multiple check scenarios
addStdLibCorpusToFuzzer -fuzzer_name FuzzBatchCheck -dir $SRC/cncf-fuzzing/projects/openfga/seed_corpus/FuzzBatchCheck || {
  if is_valid_seed_corpus /tmp/FuzzBatchCheck_seed_corpus.zip; then
    cp /tmp/FuzzBatchCheck_seed_corpus.zip $OUT/FuzzBatchCheck_seed_corpus.zip
    echo "Manually copied FuzzBatchCheck_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for FuzzStorageBackends with SQL injection and encoding tests
addStdLibCorpusToFuzzer -fuzzer_name FuzzStorageBackends -dir $SRC/cncf-fuzzing/projects/openfga/FuzzStorageBackends_seeds || {
  if is_valid_seed_corpus /tmp/FuzzStorageBackends_seed_corpus.zip; then
    cp /tmp/FuzzStorageBackends_seed_corpus.zip $OUT/FuzzStorageBackends_seed_corpus.zip
    echo "Manually copied FuzzStorageBackends_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for advanced authorization model fuzzers
addStdLibCorpusToFuzzer -fuzzer_name FuzzCheckWithExclusion -dir $SRC/cncf-fuzzing/projects/openfga/FuzzCheckWithExclusion_seeds || {
  if is_valid_seed_corpus /tmp/FuzzCheckWithExclusion_seed_corpus.zip; then
    cp /tmp/FuzzCheckWithExclusion_seed_corpus.zip $OUT/FuzzCheckWithExclusion_seed_corpus.zip
    echo "Manually copied FuzzCheckWithExclusion_seed_corpus.zip to \$OUT"
  fi
}

addStdLibCorpusToFuzzer -fuzzer_name FuzzCheckWithIntersection -dir $SRC/cncf-fuzzing/projects/openfga/FuzzCheckWithIntersection_seeds || {
  if is_valid_seed_corpus /tmp/FuzzCheckWithIntersection_seed_corpus.zip; then
    cp /tmp/FuzzCheckWithIntersection_seed_corpus.zip $OUT/FuzzCheckWithIntersection_seed_corpus.zip
    echo "Manually copied FuzzCheckWithIntersection_seed_corpus.zip to \$OUT"
  fi
}

addStdLibCorpusToFuzzer -fuzzer_name FuzzCheckWithComputedUserset -dir $SRC/cncf-fuzzing/projects/openfga/FuzzCheckWithComputedUserset_seeds || {
  if is_valid_seed_corpus /tmp/FuzzCheckWithComputedUserset_seed_corpus.zip; then
    cp /tmp/FuzzCheckWithComputedUserset_seed_corpus.zip $OUT/FuzzCheckWithComputedUserset_seed_corpus.zip
    echo "Manually copied FuzzCheckWithComputedUserset_seed_corpus.zip to \$OUT"
  fi
}

addStdLibCorpusToFuzzer -fuzzer_name FuzzCheckWithPublicAccess -dir $SRC/cncf-fuzzing/projects/openfga/FuzzCheckWithPublicAccess_seeds || {
  if is_valid_seed_corpus /tmp/FuzzCheckWithPublicAccess_seed_corpus.zip; then
    cp /tmp/FuzzCheckWithPublicAccess_seed_corpus.zip $OUT/FuzzCheckWithPublicAccess_seed_corpus.zip
    echo "Manually copied FuzzCheckWithPublicAccess_seed_corpus.zip to \$OUT"
  fi
}

addStdLibCorpusToFuzzer -fuzzer_name FuzzCheckWithMultipleRestrictions -dir $SRC/cncf-fuzzing/projects/openfga/FuzzCheckWithMultipleRestrictions_seeds || {
  if is_valid_seed_corpus /tmp/FuzzCheckWithMultipleRestrictions_seed_corpus.zip; then
    cp /tmp/FuzzCheckWithMultipleRestrictions_seed_corpus.zip $OUT/FuzzCheckWithMultipleRestrictions_seed_corpus.zip
    echo "Manually copied FuzzCheckWithMultipleRestrictions_seed_corpus.zip to \$OUT"
  fi
}

addStdLibCorpusToFuzzer -fuzzer_name FuzzCheckWithConditions -dir $SRC/cncf-fuzzing/projects/openfga/FuzzCheckWithConditions_seeds || {
  if is_valid_seed_corpus /tmp/FuzzCheckWithConditions_seed_corpus.zip; then
    cp /tmp/FuzzCheckWithConditions_seed_corpus.zip $OUT/FuzzCheckWithConditions_seed_corpus.zip
    echo "Manually copied FuzzCheckWithConditions_seed_corpus.zip to \$OUT"
  fi
}

addStdLibCorpusToFuzzer -fuzzer_name FuzzCheckWithParentChild -dir $SRC/cncf-fuzzing/projects/openfga/FuzzCheckWithParentChild_seeds || {
  if is_valid_seed_corpus /tmp/FuzzCheckWithParentChild_seed_corpus.zip; then
    cp /tmp/FuzzCheckWithParentChild_seed_corpus.zip $OUT/FuzzCheckWithParentChild_seed_corpus.zip
    echo "Manually copied FuzzCheckWithParentChild_seed_corpus.zip to \$OUT"
  fi
}

# Add seed corpus for bug-finding fuzzers
addStdLibCorpusToFuzzer -fuzzer_name FuzzPublicUsersetConfusion -dir $SRC/cncf-fuzzing/projects/openfga/FuzzPublicUsersetConfusion_seeds || {
  if is_valid_seed_corpus /tmp/FuzzPublicUsersetConfusion_seed_corpus.zip; then
    cp /tmp/FuzzPublicUsersetConfusion_seed_corpus.zip $OUT/FuzzPublicUsersetConfusion_seed_corpus.zip
    echo "Manually copied FuzzPublicUsersetConfusion_seed_corpus.zip to \$OUT"
  fi
}

addStdLibCorpusToFuzzer -fuzzer_name FuzzWildcardTupleset -dir $SRC/cncf-fuzzing/projects/openfga/FuzzWildcardTupleset_seeds || {
  if is_valid_seed_corpus /tmp/FuzzWildcardTupleset_seed_corpus.zip; then
    cp /tmp/FuzzWildcardTupleset_seed_corpus.zip $OUT/FuzzWildcardTupleset_seed_corpus.zip
    echo "Manually copied FuzzWildcardTupleset_seed_corpus.zip to \$OUT"
  fi
}

addStdLibCorpusToFuzzer -fuzzer_name FuzzModelUpdateBypass -dir $SRC/cncf-fuzzing/projects/openfga/FuzzModelUpdateBypass_seeds || {
  if is_valid_seed_corpus /tmp/FuzzModelUpdateBypass_seed_corpus.zip; then
    cp /tmp/FuzzModelUpdateBypass_seed_corpus.zip $OUT/FuzzModelUpdateBypass_seed_corpus.zip
    echo "Manually copied FuzzModelUpdateBypass_seed_corpus.zip to \$OUT"
  fi
}

# Remove any empty seed corpus zip files from $OUT
echo "Checking for and removing empty seed corpus files..."
for zip_file in $OUT/*_seed_corpus.zip; do
  if [ -f "$zip_file" ]; then
    if ! is_valid_seed_corpus "$zip_file"; then
      echo "Removing empty seed corpus: $(basename $zip_file)"
      rm "$zip_file"
    fi
  fi
done

