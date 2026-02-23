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


# gitops-engine fuzzers
cd $SRC/gitops-engine
mv $SRC/cncf-fuzzing/projects/argo/gitops-eng_diff_fuzzer.go ./pkg/diff/
compile_go_fuzzer github.com/argoproj/gitops-engine/pkg/diff FuzzGitopsDiff fuzz_gitops_diff

cd $SRC/argo-rollouts
go mod tidy
mv analysis/controller_test.go analysis/controller_test_fuzz.go
cp $SRC/cncf-fuzzing/projects/argo/rollouts-analysis-fuzzer.go $SRC/argo-rollouts/analysis/
compile_go_fuzzer github.com/argoproj/argo-rollouts/analysis FuzzreconcileAnalysisRun fuzz_reconcile_analysis_run

mv $SRC/cncf-fuzzing/projects/argo/rollouts-metrics_fuzzer.go \
   $SRC/argo-rollouts/metricproviders/webmetric//
compile_go_fuzzer github.com/argoproj/argo-rollouts/metricproviders/webmetric FuzzNewWebMetricJsonParser fuzz_new_web_metric_json_parser

mv $SRC/argo-rollouts/metricproviders/prometheus/prometheus_test.go \
   $SRC/argo-rollouts/metricproviders/prometheus/prometheus_test_fuzz.go
mv $SRC/argo-rollouts/metricproviders/prometheus/mock_test.go \
   $SRC/argo-rollouts/metricproviders/prometheus/mock_test_fuzz.go
mv $SRC/cncf-fuzzing/projects/argo/rollouts-prometheus_fuzzer.go \
   $SRC/argo-rollouts/metricproviders/prometheus/
compile_go_fuzzer github.com/argoproj/argo-rollouts/metricproviders/prometheus FuzzPrometheusProvider fuzz_prometheus_provider

mv $SRC/argo-rollouts/metricproviders/kayenta/kayenta_test.go \
   $SRC/argo-rollouts/metricproviders/kayenta/kayenta_test_fuzz.go
mv $SRC/cncf-fuzzing/projects/argo/rollouts-kayenta_fuzzer.go \
   $SRC/argo-rollouts/metricproviders/kayenta/
compile_go_fuzzer github.com/argoproj/argo-rollouts/metricproviders/kayenta FuzzKayenta fuzz_kayenta_provider

mv $SRC/cncf-fuzzing/projects/argo/rollouts-validation-fuzzer.go \
   $SRC/argo-rollouts/pkg/apis/rollouts/validation/
compile_go_fuzzer github.com/argoproj/argo-rollouts/pkg/apis/rollouts/validation FuzzValidateRollout fuzz_validate_rollout

mv $SRC/cncf-fuzzing/projects/argo/rollouts-evaluate-fuzzer.go \
   $SRC/argo-rollouts/utils/evaluate/
compile_go_fuzzer github.com/argoproj/argo-rollouts/utils/evaluate FuzzEvalCondition fuzz_eval_condition

# argo-events fuzzers
cd $SRC/argo-events
go get github.com/AdamKorcz/go-118-fuzz-build/testing

# Rename test files so helpers are accessible to fuzz builds
mv $SRC/argo-events/pkg/sensors/triggers/argo-workflow/argo-workflow_test.go \
	$SRC/argo-events/pkg/sensors/triggers/argo-workflow/argo-workflow_test_fuzz.go

# Commenting out these lines. Otherwise the fuzzers will hang:
sed -i 's/route\.DataCh <- data/\/\/route\.DataCh <- data\n\t_ = data/g' $SRC/argo-events/pkg/eventsources/sources/stripe/start.go
sed -i 's/route\.DataCh <- eventBody/\/\/route\.DataCh <- eventBody\n\t_ = eventBody/g' $SRC/argo-events/pkg/eventsources/sources/github/start.go
sed -i 's/route\.DataCh <- eventBytes/\/\/route\.DataCh <- eventBytes\n\t_ = eventBytes/g' $SRC/argo-events/pkg/eventsources/sources/awssns/start.go
sed -i 's/route\.DataCh <- data/\/\/route\.DataCh <- data\n\t_ = data/g' $SRC/argo-events/pkg/eventsources/sources/slack/start.go

# Gitlab and Bitbucket use webhook.DispatchEvent which blocks on DispatchChan
sed -i 's/webhook\.DispatchEvent(route, eventBody, logger, writer)/\/\/webhook.DispatchEvent(route, eventBody, logger, writer)\n\t_ = eventBody/g' $SRC/argo-events/pkg/eventsources/sources/gitlab/start.go
sed -i 's/webhook\.DispatchEvent(route, eventBody, logger, writer)/\/\/webhook.DispatchEvent(route, eventBody, logger, writer)\n\t_ = eventBody/g' $SRC/argo-events/pkg/eventsources/sources/bitbucket/start.go

# All argo-events fuzzers now live in the source tree as native Go fuzz tests
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/eventsources/sources/stripe FuzzStripeEventsource fuzz_stripe_eventsource
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/eventsources/sources/github FuzzGithubEventsource fuzz_github_eventsource
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/eventsources/sources/github FuzzGithubWebhookSignature fuzz_github_webhook_signature
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/eventsources/sources/awssns FuzzAWSSNSsource fuzz_awssns_eventsource
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/eventsources/sources/slack FuzzSlackEventsource fuzz_slack_eventsource
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/eventsources/sources/slack FuzzSlackWebhookSignature fuzz_slack_webhook_signature
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/sensors/triggers FuzzConstructPayload fuzz_construct_payload
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/sensors/triggers FuzzApplyParams fuzz_apply_params
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/reconciler/eventbus FuzzEventbusReconciler fuzz_eventbus_reconciler
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/reconciler/sensor FuzzSensorControllerreconcile fuzz_sensor_controller
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/reconciler/sensor FuzzSensorControllerReconcile fuzz_sensor_controller_reconcile
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/sensors FuzzGetDependencyExpression fuzz_get_dependency_expression
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/sensors/triggers/argo-workflow FuzzArgoWorkflowTriggerExecute fuzz_events_argo_workflow_trigger_execute
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/shared/expr FuzzExpr fuzz_expr
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/shared/expr FuzzJsonPath fuzz_json_path
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/reconciler/sensor FuzzValidateSensor fuzz_validate_sensor

zip $OUT/fuzz_expr_seed_corpus.zip $SRC/cncf-fuzzing/projects/argo/seeds/fuzz_expr/*

compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/eventsources/sources/gitlab FuzzGitlabEventsource fuzz_gitlab_eventsource
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/eventsources/sources/bitbucket FuzzBitbucketEventsource fuzz_bitbucket_eventsource

compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/reconciler/eventsource FuzzEventsourceReconciler fuzz_eventsource_reconciler
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/reconciler/eventsource FuzzResourceReconcile fuzz_resource_reconcile
compile_native_go_fuzzer github.com/argoproj/argo-events/pkg/reconciler/eventsource FuzzValidateEventSource fuzz_validate_event_source

# argo-cd fuzzers
cd $SRC/argo-cd
go mod tidy
go get github.com/AdaLogics/go-fuzz-headers
mv $SRC/cncf-fuzzing/projects/argo/project_fuzzer.go $SRC/argo-cd/server/project/
mv $SRC/argo-cd/server/project/project_test.go $SRC/argo-cd/server/project/project_test_fuzz.go
compile_go_fuzzer github.com/argoproj/argo-cd/v3/server/project FuzzValidateProject fuzz_validate_project
compile_go_fuzzer github.com/argoproj/argo-cd/v3/server/project FuzzParseUnverified fuzz_parse_unverified
compile_go_fuzzer github.com/argoproj/argo-cd/v3/server/project FuzzCreateToken fuzz_create_token

mv $SRC/cncf-fuzzing/projects/argo/argo-cd_db_fuzzer.go $SRC/argo-cd/util/db/
mv $SRC/argo-cd/util/db/certificate_test.go $SRC/argo-cd/util/db/certificate_test_fuzz.go
mv $SRC/argo-cd/util/db/db_test.go $SRC/argo-cd/util/db/db_test_fuzz.go
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/db FuzzCreateRepoCertificate fuzz_create_repo_certificate

mv $SRC/cncf-fuzzing/projects/argo/argo-cd_util_grpc_fuzzer.go $SRC/argo-cd/util/grpc/
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/grpc FuzzUserAgentUnaryServerInterceptor fuzz_user_agent_unary_server_interceptor
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/grpc FuzzuserAgentEnforcer fuzz_user_agent_enforcer

mv $SRC/cncf-fuzzing/projects/argo/argo-cd_rbac_fuzzer.go $SRC/argo-cd/util/rbac/
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/rbac FuzzLoadPolicy fuzz_load_policy
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/rbac FuzzEnforce fuzz_enforce

mv $SRC/cncf-fuzzing/projects/argo/argo-cd_resource_tracking_fuzzer.go $SRC/argo-cd/util/argo/
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/argo FuzzParseAppInstanceValue fuzz_parse_app_instance_value
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/argo FuzzGetAppName fuzz_get_app_name

mv $SRC/cncf-fuzzing/projects/argo/gpg_fuzzer.go $SRC/argo-cd/util/gpg/
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/gpg FuzzImportPGPKeys fuzz_import_pgp_keys
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/gpg FuzzValidatePGPKeysFromString fuzz_validate_pgp_keys

mv $SRC/cncf-fuzzing/projects/argo/diff_fuzzer.go $SRC/argo-cd/util/argo/diff/
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/argo/diff FuzzStateDiff fuzz_state_diff

mv $SRC/cncf-fuzzing/projects/argo/sessionmanager_fuzzer.go $SRC/argo-cd/util/session/
mv $SRC/argo-cd/util/session/sessionmanager_test.go $SRC/argo-cd/util/session/sessionmanager_fuzz.go
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/session FuzzSessionmanagerParse fuzz_sessionmanager_parse
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/session FuzzVerifyUsernamePassword fuzz_verify_username_password

mv $SRC/cncf-fuzzing/projects/argo/repository_fuzzer.go $SRC/argo-cd/reposerver/repository/
compile_go_fuzzer github.com/argoproj/argo-cd/v3/reposerver/repository FuzzGenerateManifests fuzz_generate_manifests

mv $SRC/cncf-fuzzing/projects/argo/normalizer_fuzzer.go $SRC/argo-cd/util/argo/normalizers/
compile_go_fuzzer github.com/argoproj/argo-cd/v3/util/argo/normalizers FuzzNormalize fuzz_normalize


# argo-workflows fuzzers
cd $SRC/argo-workflows
go mod tidy
go get github.com/AdaLogics/go-fuzz-headers
go get github.com/aws/aws-sdk-go-v2/internal/ini@latest

mv $SRC/cncf-fuzzing/projects/argo/workflow_server_fuzzer.go $SRC/argo-workflows/server/workflow/
mv $SRC/argo-workflows/server/workflow/workflow_server_test.go $SRC/argo-workflows/server/workflow/workflow_server_test_fuzz.go 
mv $SRC/argo-workflows/server/workflow/test_server_stream_test.go $SRC/argo-workflows/server/workflow/test_server_stream_test_fuzz.go
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/server/workflow FuzzWorkflowServer fuzz_workflow_server
# seed files:
zip -r $OUT/fuzz_workflow_server_seed_corpus.zip $SRC/cncf-fuzzing/projects/argo/seeds/workflow_server_fuzzer/*


# Artifacts fuzzers disabled: testing.RunTests crashes in go-fuzz binary context
# mv $SRC/cncf-fuzzing/projects/argo/artifacts_fuzzer.go $SRC/argo-workflows/server/artifacts/
# mv $SRC/argo-workflows/server/artifacts/artifact_server_test.go $SRC/argo-workflows/server/artifacts/artifact_server_test_fuzz.go
# compile_go_fuzzer github.com/argoproj/argo-workflows/v3/server/artifacts FuzzGetOutputArtifact fuzz_get_output_artifact
# compile_go_fuzzer github.com/argoproj/argo-workflows/v3/server/artifacts FuzzGetOutputArtifactByUID fuzz_get_output_artifact_by_uuid

mv $SRC/cncf-fuzzing/projects/argo/ancestry_fuzzer.go $SRC/argo-workflows/workflow/common/
mv $SRC/argo-workflows/workflow/common/ancestry_test.go $SRC/argo-workflows/workflow/common/ancestry_test_fuzz.go 
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/common FuzzGetTaskDependencies fuzz_get_task_dependencies

#rm /root/go/pkg/mod/github.com/aws/aws-sdk-go-v2/internal/ini@v1.3.10/fuzz.go
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
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/cron FuzzCronValidation fuzz_cron_validation

mv $SRC/cncf-fuzzing/projects/argo/workflow_validation_fuzzer.go $SRC/argo-workflows/workflow/validate/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/validate FuzzValidateWorkflow fuzz_validate_workflow

mv $SRC/cncf-fuzzing/projects/argo/workflow_parser_fuzzer.go $SRC/argo-workflows/workflow/common/
compile_go_fuzzer github.com/argoproj/argo-workflows/v3/workflow/common FuzzParseObjects fuzz_parse_objects

zip $OUT/fuzz_get_dependency_expression_seed_corpus.zip $SRC/argo-events/examples/sensors/trigger-with-template.yaml

cp $SRC/cncf-fuzzing/projects/argo/dictionaries/* $OUT/
