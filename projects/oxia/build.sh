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
mkdir -p $SRC/oxia/oxia/fuzz
cp $SRC/cncf-fuzzing/projects/oxia/*.go $SRC/oxia/oxia/fuzz/

# Copy seed corpus to the fuzz directory
echo "Setting up seed corpus"
if [ -d "$SRC/cncf-fuzzing/projects/oxia/testdata" ]; then
  cp -r $SRC/cncf-fuzzing/projects/oxia/testdata $SRC/oxia/oxia/fuzz/
  echo "Copied seed corpus from cncf-fuzzing to oxia/fuzz"
fi

# Consolidate Go workspace into a single module so that the coverage build
# instruments ALL packages (common, oxia, oxiad) instead of just the module
# containing the fuzz tests. Without this, -coverpkg only covers the "oxia"
# module and misses kvstore, wal, compare, model, controller, etc.
echo "Consolidating Go modules for coverage support"
cd $SRC/oxia
rm -f go.work
rm -f cmd/go.mod cmd/go.sum
rm -f common/go.mod common/go.sum
rm -f oxia/go.mod oxia/go.sum
rm -f oxiad/go.mod oxiad/go.sum
rm -f tests/go.mod tests/go.sum

cat > go.mod << 'EOF'
module github.com/oxia-db/oxia

go 1.25
EOF

go mod tidy

fuzz_targets1=(
	FuzzKVPutGet
	FuzzKVRangeScan
	FuzzKVDeleteRange
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

cd $SRC/oxia/oxia/fuzz
PKG="github.com/oxia-db/oxia/oxia/fuzz"
for f in "${fuzz_targets1[@]}"; do
  compile_native_go_fuzzer_v2 "$PKG" "$f" "$f"
done
