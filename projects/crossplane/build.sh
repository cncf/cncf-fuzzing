#!/bin/bash -eu
# Copyright 2022 Ada Logics Ltd
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

export CNCF="${SRC}/cncf-fuzzing/projects/crossplane"

mv $CNCF/xpkg_fuzzer.go $SRC/crossplane/internal/xpkg/
mv $CNCF/composition_fuzzer.go $SRC/crossplane/internal/controller/apiextensions/composition/
mv $CNCF/composite_fuzzer.go $SRC/crossplane/internal/controller/apiextensions/composite/
mv $CNCF/manager_fuzzer.go $SRC/crossplane/internal/controller/pkg/manager/
mv $CNCF/revision_fuzzer.go $SRC/crossplane/internal/controller/pkg/revision/
mv $CNCF/xcrd_fuzzer.go $SRC/crossplane/internal/xcrd/
mv $CNCF/patch_fuzzer.go $SRC/crossplane/apis/apiextensions/v1/
mv $CNCF/dag_fuzzer.go $SRC/crossplane/internal/dag/
mv $CNCF/claims_fuzzer.go $SRC/crossplane/internal/controller/apiextensions/claim/
go mod tidy
rm /root/go/pkg/mod/github.com/aws/aws-sdk-go-v2/internal/ini@v1.3.11/fuzz.go

compile_go_fuzzer github.com/crossplane/crossplane/apis/apiextensions/v1 FuzzPatchApply fuzz_patch_apply
compile_go_fuzzer github.com/crossplane/crossplane/apis/apiextensions/v1 FuzzTransform fuzz_transform
compile_go_fuzzer github.com/crossplane/crossplane/internal/xpkg FuzzParse fuzz_parse
compile_go_fuzzer github.com/crossplane/crossplane/internal/controller/apiextensions/claim FuzzPropagateConnection fuzz_propagate_connection
compile_go_fuzzer github.com/crossplane/crossplane/internal/controller/apiextensions/composition FuzzNewCompositionRevision fuzz_NewCompositionRevision
compile_go_fuzzer github.com/crossplane/crossplane/internal/controller/apiextensions/composite FuzzAsComposition fuzz_AsComposition
compile_go_fuzzer github.com/crossplane/crossplane/internal/controller/pkg/manager FuzzPackageRevision fuzz_PackageRevision
compile_go_fuzzer github.com/crossplane/crossplane/internal/controller/pkg/revision FuzzGCRExtract fuzz_gcr_extract
compile_go_fuzzer github.com/crossplane/crossplane/internal/controller/pkg/revision FuzzParseReference fuzz_parse_reference
compile_go_fuzzer github.com/crossplane/crossplane/internal/xcrd FuzzForCompositeResource fuzz_ForCompositeResource
compile_go_fuzzer github.com/crossplane/crossplane/internal/xcrd FuzzForCompositeResourceClaim fuzz_FuzzForCompositeResourceClaim
compile_go_fuzzer github.com/crossplane/crossplane/internal/xpkg FuzzFindXpkgInDir fuzz_find_xpkg_in_dir
compile_go_fuzzer github.com/crossplane/crossplane/internal/dag FuzzDag fuzz_dag
