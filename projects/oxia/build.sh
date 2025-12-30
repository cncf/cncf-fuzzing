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
wget https://go.dev/dl/go1.25.3.linux-amd64.tar.gz

mkdir temp-go
tar -C temp-go/ -xzf go1.25.3.linux-amd64.tar.gz

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
cd $SRC/oxia


echo building fuzzers
# Copy fuzzers directly to oxia directory (not a subdirectory)
# so they are part of the github.com/oxia-db/oxia/oxia module
cp $SRC/cncf-fuzzing/projects/oxia/*_test.go $SRC/oxia/oxia/

# Copy seed corpus to the oxia directory
echo "Setting up seed corpus"
if [ -d "$SRC/cncf-fuzzing/projects/oxia/testdata" ]; then
  cp -r $SRC/cncf-fuzzing/projects/oxia/testdata $SRC/oxia/oxia/
  echo "Copied seed corpus from cncf-fuzzing to oxia"
fi

fuzz_targets1=(
	FuzzKVRangeScan
	FuzzKVComparisonTypes
	FuzzKVKeyOrdering
	FuzzMetadataLoadStore
	FuzzMetadataLeaderHelper
	FuzzE2EOperations
	FuzzShardStatusUnmarshalInvalid
	FuzzServerGetIdentifier
	FuzzWalAppendRead
	FuzzWalMultipleEntries
	FuzzHierarchicalEncodeDecode
	FuzzNaturalEncodeDecode
	FuzzEncodingPreservesOrder
	FuzzHierarchicalSortingProperties
	FuzzCompareWithSlashProperties
	FuzzSortingStability
	FuzzDatabaseRangeOperations
	FuzzDatabaseKeyValidation
)

cd $SRC/oxia/oxia
PKG="github.com/oxia-db/oxia/oxia"

for f in "${fuzz_targets1[@]}"; do
  compile_native_go_fuzzer_v2 "$PKG" "$f" "$f"
done

# For coverage builds, patch all fuzzers to cover all Oxia modules
# The default only covers the single module where the fuzzer lives
if [[ $SANITIZER == *coverage* ]]; then
  echo "Patching coverage instrumentation to include all Oxia modules"
  
  for f in "${fuzz_targets1[@]}"; do
    # Rebuild the test binary with expanded coverpkg
    # Must list each workspace module explicitly because of go.work
    cd $SRC/oxia/oxia
    go test -c \
      -o "$OUT/$f" \
      -tags gofuzz \
      -coverpkg="github.com/oxia-db/oxia/oxia/...,github.com/oxia-db/oxia/oxiad/...,github.com/oxia-db/oxia/common/...,github.com/oxia-db/oxia/cmd/...,github.com/oxia-db/oxia/tests/..." \
      -covermode=atomic \
      "$PKG"
    
    echo "Rebuilt $f with full repo coverage (all workspace modules)"
  done
fi

# Copy .options files if they exist
echo "Copying fuzzer options files"
for f in "${fuzz_targets1[@]}"; do
  if [ -f "$SRC/cncf-fuzzing/projects/oxia/${f}.options" ]; then
    cp "$SRC/cncf-fuzzing/projects/oxia/${f}.options" "$OUT/${f}.options"
    echo "Copied ${f}.options to \$OUT"
  fi
done

# Convert native Go seed corpus to libFuzzer format using go-118-fuzz-build tool
echo "Converting seed corpus to libFuzzer format"
for f in "${fuzz_targets1[@]}"; do
  # Check if seed corpus exists for this fuzzer
  if [ -d "$SRC/cncf-fuzzing/projects/oxia/testdata/fuzz/$f" ]; then
    echo "Processing corpus for $f"
    addStdLibCorpusToFuzzer -fuzzer_name "$f" -dir "$SRC/cncf-fuzzing/projects/oxia/testdata/fuzz/$f" || {
      echo "Warning: addStdLibCorpusToFuzzer failed for $f, checking for manual corpus"
      if [ -f "/tmp/${f}_seed_corpus.zip" ]; then
        cp "/tmp/${f}_seed_corpus.zip" "$OUT/${f}_seed_corpus.zip"
        echo "Manually copied ${f}_seed_corpus.zip to \$OUT"
      fi
    }
  fi
done

echo "Seed corpus setup complete"

# Remove empty seed corpus zip files to prevent OSS-Fuzz run_fuzzer script issues
echo "Checking for empty seed corpus zip files"
for zipfile in "$OUT"/*_seed_corpus.zip; do
  if [ -f "$zipfile" ]; then
    # Check if zip file is empty (less than 100 bytes typically means empty)
    size=$(stat -c%s "$zipfile" 2>/dev/null || echo "0")
    if [ "$size" -lt 100 ]; then
      echo "Removing empty seed corpus: $(basename "$zipfile") (size: $size bytes)"
      rm "$zipfile"
    fi
  fi
done
