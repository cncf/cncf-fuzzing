#!/bin/bash -eu
set -o nounset
set -o pipefail
set -o errexit
set -x

mv $SRC/cncf-fuzzing/projects/helm/fs_fuzzer.go \
   $SRC/helm/internal/third_party/dep/fs/

mv $SRC/cncf-fuzzing/projects/helm/chart_fuzzer.go \
   $SRC/helm/pkg/chart/

mv $SRC/cncf-fuzzing/projects/helm/engine_fuzzer.go \
   $SRC/helm/pkg/engine/

mv $SRC/cncf-fuzzing/projects/helm/action_fuzzer.go \
   $SRC/helm/pkg/action/
mv $SRC/helm/pkg/action/list_test.go \
   $SRC/helm/pkg/action/list_test_fuzz.go

mv $SRC/helm/pkg/action/upgrade_test.go $SRC/helm/pkg/action/upgrade_test_fuzz.go
mv /src/helm/pkg/action/action_test.go $SRC/helm/pkg/action/action_test_fuzz.go

mv $SRC/cncf-fuzzing/projects/helm/loaddir_fuzzer.go \
   $SRC/helm/pkg/chart/loader/

mv $SRC/cncf-fuzzing/projects/helm/chartutil_fuzzer.go \
   $SRC/helm/pkg/chartutil/

mv $SRC/cncf-fuzzing/projects/helm/driver_fuzzer.go \
   $SRC/helm/pkg/storage/driver/
mv $SRC/helm/pkg/storage/driver/mock_test.go \
   $SRC/helm/pkg/storage/driver/mock_test_fuzz.go

mv $SRC/cncf-fuzzing/projects/helm/repo_fuzzer.go \
   $SRC/helm/pkg/repo/

mv $SRC/cncf-fuzzing/projects/helm/registry_fuzzer.go \
   $SRC/helm/pkg/registry/

mv $SRC/cncf-fuzzing/projects/helm/plugin_fuzzer.go \
   $SRC/helm/pkg/plugin/

mv $SRC/cncf-fuzzing/projects/helm/kube_fuzzer.go \
   $SRC/helm/pkg/kube/
mv $SRC/helm/pkg/kube/client_test.go \
   $SRC/helm/pkg/kube/client_fuzz.go

mv $SRC/cncf-fuzzing/projects/helm/provenance_fuzzer.go \
   $SRC/helm/pkg/provenance/

mv $SRC/cncf-fuzzing/projects/helm/storage_fuzzer.go \
   $SRC/helm/pkg/storage/

go mod download && go mod tidy
compile_go_fuzzer helm.sh/helm/v3/pkg/storage FuzzStorage fuzz_storage
compile_go_fuzzer helm.sh/helm/v3/pkg/provenance FuzzNewFromFiles fuzz_new_from_files
compile_go_fuzzer helm.sh/helm/v3/pkg/provenance FuzzParseMessageBlock fuzz_parse_message_block
compile_go_fuzzer helm.sh/helm/v3/pkg/provenance FuzzMessageBlock fuzz_message_block
compile_go_fuzzer helm.sh/helm/v3/pkg/kube FuzzKubeClient fuzz_kube_client
compile_go_fuzzer helm.sh/helm/v3/pkg/registry FuzzGetTagMatchingVersionOrConstraint fuzz_get_tag_matching_version_or_constraint
compile_go_fuzzer helm.sh/helm/v3/pkg/registry FuzzparseReference fuzz_parse_reference
compile_go_fuzzer helm.sh/helm/v3/pkg/plugin FuzzFindPlugins fuzz_find_plugins
compile_go_fuzzer helm.sh/helm/v3/pkg/plugin FuzzLoadAll fuzz_load_all
compile_go_fuzzer helm.sh/helm/v3/internal/third_party/dep/fs FuzzfixLongPath fuzz_fix_long_path
compile_go_fuzzer helm.sh/helm/v3/internal/third_party/dep/fs Fuzz_fixLongPath fuzz_fix_long_path_internal
compile_go_fuzzer helm.sh/helm/v3/pkg/storage/driver FuzzSqlDriver fuzz_sql_driver
compile_go_fuzzer helm.sh/helm/v3/pkg/storage/driver FuzzRecords fuzz_records
compile_go_fuzzer helm.sh/helm/v3/pkg/storage/driver FuzzSecrets fuzz_secrets
compile_go_fuzzer helm.sh/helm/v3/pkg/storage/driver FuzzMemory fuzz_memory
compile_go_fuzzer helm.sh/helm/v3/pkg/storage/driver FuzzCfgmaps fuzz_cfgmaps
compile_go_fuzzer helm.sh/helm/v3/pkg/chart FuzzMetadataValidate fuzz_metadata_validate
compile_go_fuzzer helm.sh/helm/v3/pkg/chart FuzzDependencyValidate fuzz_dependency_validate
compile_go_fuzzer helm.sh/helm/v3/pkg/engine FuzzEngineRender fuzz_engine_render
compile_go_fuzzer helm.sh/helm/v3/pkg/action FuzzActionRun fuzz_action_run
compile_go_fuzzer helm.sh/helm/v3/pkg/action FuzzShowRun fuzz_show_run
compile_go_fuzzer helm.sh/helm/v3/pkg/action FuzzDependencyList fuzz_dependency_list
compile_go_fuzzer helm.sh/helm/v3/pkg/action FuzzActionList fuzz_action_list
compile_go_fuzzer helm.sh/helm/v3/pkg/chart/loader FuzzLoadDir fuzz_load_dir
compile_go_fuzzer helm.sh/helm/v3/pkg/chartutil FuzzProcessDependencies fuzz_process_dependencies
compile_go_fuzzer helm.sh/helm/v3/pkg/chartutil FuzzIsChartDir fuzz_is_chart_dir
compile_go_fuzzer helm.sh/helm/v3/pkg/chartutil FuzzExpandFile fuzz_expand_file
compile_go_fuzzer helm.sh/helm/v3/pkg/chartutil FuzzCreateFrom fuzz_create_from
compile_go_fuzzer helm.sh/helm/v3/pkg/repo FuzzIndex fuzz_index
compile_go_fuzzer helm.sh/helm/v3/pkg/repo FuzzIndexDirectory fuzz_index_directory
compile_go_fuzzer helm.sh/helm/v3/pkg/repo FuzzDownloadIndexFile fuzz_download_index_file
compile_go_fuzzer helm.sh/helm/v3/pkg/repo FuzzWriteFile fuzz_write_file

sed 's/go 1.16/go 1.18/g' -i $SRC/helm/go.mod

mv $SRC/cncf-fuzzing/projects/helm/strvals_fuzzer_test.go \
   $SRC/helm/pkg/strvals/

mv $SRC/cncf-fuzzing/projects/helm/ignore_fuzzer_test.go \
   $SRC/helm/internal/ignore/

gotip mod download && gotip mod tidy
gotip get github.com/AdamKorcz/go-118-fuzz-build/utils
compile_native_go_fuzzer helm.sh/helm/v3/internal/ignore FuzzIgnoreParse fuzz_ignore_parse
compile_native_go_fuzzer helm.sh/helm/v3/pkg/strvals FuzzStrvalsParse fuzz_strvals_parse

zip $OUT/fuzz_create_from_seed_corpus.zip $SRC/helm/pkg/chartutil/testdata/frobnitz/*
mv $SRC/cncf-fuzzing/projects/helm/dicts/fuzz_create_from.dict $OUT/