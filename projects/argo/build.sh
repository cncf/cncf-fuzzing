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

apt-get update && apt-get install -y zip

# gitops-engine fuzzers
cd $SRC 
git clone https://github.com/argoproj/gitops-engine 
cd gitops-engine
mv $SRC/cncf-fuzzing/projects/argo/gitops-eng_diff_fuzzer.go ./pkg/diff/
compile_go_fuzzer github.com/argoproj/gitops-engine/pkg/diff FuzzGitopsDiff fuzz_gitops_diff


# argo-events fuzzers
cd $SRC/argo-events
mv $SRC/cncf-fuzzing/projects/argo/eventbus_controller_fuzzer.go $SRC/argo-events/controllers/eventbus/
mv $SRC/cncf-fuzzing/projects/argo/eventsource_controller_fuzzer.go $SRC/argo-events/controllers/eventsource/
mv $SRC/cncf-fuzzing/projects/argo/sensor_controller_fuzzer.go $SRC/argo-events/controllers/sensor/
compile_go_fuzzer github.com/argoproj/argo-events/controllers/eventbus FuzzEventbusReconciler fuzz_eventbus_reconciler
compile_go_fuzzer github.com/argoproj/argo-events/controllers/sensor FuzzSensorController fuzz_sensor_controller
compile_go_fuzzer github.com/argoproj/argo-events/controllers/sensor FuzzSensorControllerReconcile fuzz_sensor_controller_reconcile



if [ "$SANITIZER" = "address" ]
then
	# These fuzzer need to link with ztsd

	echo "building fuzz_eventsource_reconciler"
	go-fuzz -tags gofuzz -func FuzzEventsourceReconciler -o FuzzEventsourceReconciler.a github.com/argoproj/argo-events/controllers/eventsource
	$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzEventsourceReconciler.a /src/zstd-1.4.2/lib/libzstd.a -lpthread -o $OUT/fuzz_eventsource_reconciler

	echo "building fuzz_resource_reconcile"
	go-fuzz -tags gofuzz -func FuzzResourceReconcile -o FuzzResourceReconcile.a github.com/argoproj/argo-events/controllers/eventsource
	$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzResourceReconcile.a /src/zstd-1.4.2/lib/libzstd.a -lpthread -o $OUT/fuzz_resource_reconcile

	echo "building fuzz_validate_event_source"
	mv $SRC/cncf-fuzzing/projects/argo/validate_event_source_fuzzer.go $SRC/argo-events/controllers/eventsource/
	go-fuzz -tags gofuzz -func FuzzValidateEventSource -o FuzzValidateEventSource.a github.com/argoproj/argo-events/controllers/eventsource
	$CXX $CXXFLAGS $LIB_FUZZING_ENGINE FuzzValidateEventSource.a /src/zstd-1.4.2/lib/libzstd.a -lpthread -o $OUT/fuzz_validate_event_source
fi

# argo-cd fuzzers
cd $SRC/argo-cd
mv $SRC/cncf-fuzzing/projects/argo/project_fuzzer.go $SRC/argo-cd/server/project/
mv $SRC/argo-cd/server/project/project_test.go $SRC/argo-cd/server/project/project_test_fuzz.go
compile_go_fuzzer github.com/argoproj/argo-cd/v2/server/project FuzzValidateProject fuzz_validate_project
compile_go_fuzzer github.com/argoproj/argo-cd/v2/server/project FuzzParseUnverified fuzz_parse_unverified
compile_go_fuzzer github.com/argoproj/argo-cd/v2/server/project FuzzCreateToken fuzz_create_token

mv $SRC/cncf-fuzzing/projects/argo/argo-cd_db_fuzzer.go $SRC/argo-cd/util/db/
mv $SRC/argo-cd/util/db/certificate_test.go $SRC/argo-cd/util/db/certificate_test_fuzz.go
mv $SRC/argo-cd/util/db/db_test.go $SRC/argo-cd/util/db/db_test_fuzz.go
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/db FuzzCreateRepoCertificate fuzz_create_repo_certificate

mv $SRC/cncf-fuzzing/projects/argo/argo-cd_util_grpc_fuzzer.go $SRC/argo-cd/util/grpc/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/grpc FuzzUserAgentUnaryServerInterceptor fuzz_user_agent_unary_server_interceptor
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/grpc FuzzuserAgentEnforcer fuzz_user_agent_enforcer

mv $SRC/cncf-fuzzing/projects/argo/argo-cd_rbac_fuzzer.go $SRC/argo-cd/util/rbac/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/rbac FuzzLoadPolicy fuzz_load_policy

mv $SRC/cncf-fuzzing/projects/argo/argo-cd_resource_tracking_fuzzer.go $SRC/argo-cd/util/argo/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/argo FuzzParseAppInstanceValue fuzz_parse_app_instance_value
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/argo FuzzGetAppName fuzz_get_app_name

mv $SRC/cncf-fuzzing/projects/argo/gpg_fuzzer.go $SRC/argo-cd/util/gpg/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/gpg FuzzImportPGPKeys fuzz_import_pgp_keys
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/gpg FuzzValidatePGPKeysFromString fuzz_validate_pgp_keys

mv $SRC/cncf-fuzzing/projects/argo/argo-cd_validate_project_fuzzer.go $SRC/argo-cd/pkg/apis/application/v1alpha1/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1 FuzzValidateAppProject fuzz_validate_app_project

mv $SRC/cncf-fuzzing/projects/argo/diff_fuzzer.go $SRC/argo-cd/util/argo/diff/
compile_go_fuzzer github.com/argoproj/argo-cd/v2/util/argo/diff FuzzStateDiff fuzz_state_diff

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

mv $SRC/cncf-fuzzing/projects/argo/workflow_server_fuzzer.go $SRC/argo-workflows/server/workflow/
mv $SRC/argo-workflows/server/workflow/workflow_server_test.go $SRC/argo-workflows/server/workflow/workflow_server_test_fuzz.go 
mv $SRC/argo-workflows/server/workflow/test_server_stream_test.go $SRC/argo-workflows/server/workflow/test_server_stream_test_fuzz.go
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/server/workflow FuzzWorkflowServer fuzz_workflow_server
# seed files:
zip -r $OUT/fuzz_workflow_server_seed_corpus.zip $SRC/cncf-fuzzing/projects/argo/seeds/workflow_server_fuzzer/*


mv $SRC/cncf-fuzzing/projects/argo/artifacts_fuzzer.go $SRC/argo-workflows/server/artifacts/
mv $SRC/argo-workflows/server/artifacts/artifact_server_test.go $SRC/argo-workflows/server/artifacts/artifact_server_test_fuzz.go 
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/server/artifacts FuzzGetOutputArtifact fuzz_get_output_artifact
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/server/artifacts FuzzGetOutputArtifactByUID fuzz_get_output_artifact_by_uuid

mv $SRC/cncf-fuzzing/projects/argo/ancestry_fuzzer.go $SRC/argo-workflows/workflow/common/
mv $SRC/argo-workflows/workflow/common/ancestry_test.go $SRC/argo-workflows/workflow/common/ancestry_test_fuzz.go 
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/common FuzzGetTaskDependencies fuzz_get_task_dependencies

mv $SRC/cncf-fuzzing/projects/argo/operator_fuzzer.go $SRC/argo-workflows/workflow/controller/
mv $SRC/argo-workflows/workflow/controller/controller_test.go $SRC/argo-workflows/workflow/controller/controller_test_fuzz.go 
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/controller FuzzOperator fuzz_operator

mv $SRC/cncf-fuzzing/projects/argo/workflow_controller_fuzzer.go $SRC/argo-workflows/workflow/controller/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/controller FuzzWorkflowController fuzz_workflow_controller

mv $SRC/cncf-fuzzing/projects/argo/workflows_sync_fuzzer.go $SRC/argo-workflows/workflow/sync/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/sync FuzzDecodeLockName fuzz_decode_lock_name

mv $SRC/cncf-fuzzing/projects/argo/workflows_sso_fuzzer.go $SRC/argo-workflows/server/auth/sso
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/server/auth/sso FuzzSSOAuthorize fuzz_sso_authorize

mv $SRC/cncf-fuzzing/projects/argo/workflow_util_fuzzer.go $SRC/argo-workflows/workflow/util/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/util FuzzSubmitWorkflow fuzz_submit_workflow

mv $SRC/cncf-fuzzing/projects/argo/workflow_cron_fuzzer.go $SRC/argo-workflows/workflow/cron/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/cron FuzzWoCRun fuzz_woc_run

mv $SRC/cncf-fuzzing/projects/argo/workflow_validation_fuzzer.go $SRC/argo-workflows/workflow/validate/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/validate FuzzValidateWorkflow fuzz_validate_workflow

mv $SRC/cncf-fuzzing/projects/argo/workflow_parser_fuzzer.go $SRC/argo-workflows/workflow/common/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/common FuzzParseObjects fuzz_parse_objects


