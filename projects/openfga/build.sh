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
)

PKG="github.com/openfga/openfga/tests"
for f in "${fuzz_targets1[@]}"; do
  compile_native_go_fuzzer_v2 "$PKG" "$f" "$f"
done
