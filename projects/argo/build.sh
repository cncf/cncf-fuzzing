#!/bin/bash -eu
# Copyright 2021 ADA Logics Ltd
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

# argo-cd fuzzers
mv $SRC/cncf-fuzzing/projects/argo/diff_fuzzer.go $SRC/argo-cd/util/argo/diff/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/argo/diff FuzzStateDiff fuzz_state_diff

mv $SRC/cncf-fuzzing/projects/argo/gpg_fuzzer.go $SRC/argo-cd/util/gpg/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/gpg FuzzImportPGPKeys fuzz_import_pgp_keys

mv $SRC/cncf-fuzzing/projects/argo/project_fuzzer.go $SRC/argo-cd/server/project/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/server/project FuzzValidateProject fuzz_validate_project
compile_go_fuzzer github.com/argoproj/argo-cd/v2/server/project FuzzParseUnverified fuzz_parse_unverified

mv $SRC/cncf-fuzzing/projects/argo/sessionmanager_fuzzer.go $SRC/argo-cd/util/session/
mv $SRC/argo-cd/util/session/sessionmanager_test.go $SRC/argo-cd/util/session/sessionmanager_fuzz.go
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/session FuzzSessionmanagerParse fuzz_sessionmanager_parse
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/session FuzzVerifyUsernamePassword fuzz_verify_username_password

mv $SRC/cncf-fuzzing/projects/argo/repository_fuzzer.go $SRC/argo-cd/reposerver/repository/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/reposerver/repository FuzzGenerateManifests fuzz_generate_manifests

mv $SRC/cncf-fuzzing/projects/argo/normalizer_fuzzer.go $SRC/argo-cd/util/argo/normalizers/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/argo/normalizers FuzzNormalize fuzz_normalize

# argo-workflows fuzzers
cd $SRC/argo-workflows
mv $SRC/cncf-fuzzing/projects/argo/workflow_util_fuzzer.go $SRC/argo-workflows/workflow/util/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/util FuzzSubmitWorkflow fuzz_submit_workflow

mv $SRC/cncf-fuzzing/projects/argo/workflow_cron_fuzzer.go $SRC/argo-workflows/workflow/cron/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/cron FuzzWoCRun fuzz_woc_run

mv $SRC/cncf-fuzzing/projects/argo/workflow_validation_fuzzer.go $SRC/argo-workflows/workflow/validate/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/validate FuzzValidateWorkflow fuzz_validate_workflow

mv $SRC/cncf-fuzzing/projects/argo/workflow_parser_fuzzer.go $SRC/argo-workflows/workflow/common/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/common FuzzParseObjects fuzz_parse_objects

mv $SRC/cncf-fuzzing/projects/argo/workflow_controller_fuzzer.go $SRC/argo-workflows/workflow/controller/
mv $SRC/argo-workflows/workflow/controller/controller_test.go $SRC/argo-workflows/workflow/controller/controller_fuzz.go
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/controller FuzzWorkflowController fuzz_workflow_controller
