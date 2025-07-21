#!/bin/bash -eu
set -o nounset
set -o pipefail
set -o errexit
set -x

mv $SRC/cncf-fuzzing/projects/helm/fs_fuzzer.go \
   $SRC/helm/internal/third_party/dep/fs/

mv $SRC/cncf-fuzzing/projects/helm/engine_fuzzer.go \
   $SRC/helm/pkg/engine/

mv $SRC/cncf-fuzzing/projects/helm/action_fuzzer.go \
   $SRC/helm/pkg/action/
mv $SRC/helm/pkg/action/list_test.go \
   $SRC/helm/pkg/action/list_test_fuzz.go

mv $SRC/helm/pkg/action/upgrade_test.go $SRC/helm/pkg/action/upgrade_test_fuzz.go
mv /src/helm/pkg/action/action_test.go $SRC/helm/pkg/action/action_test_fuzz.go
mv /src/helm/pkg/action/uninstall_test.go $SRC/helm/pkg/action/uninstall_test_fuzz.go

mv $SRC/cncf-fuzzing/projects/helm/loaddir_fuzzer.go \
   $SRC/helm/pkg/chart/v2/loader/

mv $SRC/cncf-fuzzing/projects/helm/chartutil_fuzzer.go \
   $SRC/helm/pkg/chart/v2/util/

mv $SRC/cncf-fuzzing/projects/helm/driver_fuzzer.go \
   $SRC/helm/pkg/storage/driver/
mv $SRC/helm/pkg/storage/driver/mock_test.go \
   $SRC/helm/pkg/storage/driver/mock_test_fuzz.go

mv $SRC/cncf-fuzzing/projects/helm/repo_fuzzer.go \
   $SRC/helm/pkg/repo/

mv $SRC/cncf-fuzzing/projects/helm/plugin_fuzzer.go \
   $SRC/helm/pkg/plugin/

mv $SRC/cncf-fuzzing/projects/helm/kube_fuzzer.go \
   $SRC/helm/pkg/kube/
mv $SRC/helm/pkg/kube/client_test.go \
   $SRC/helm/pkg/kube/client_fuzz.go
mv $SRC/helm/pkg/kube/ready_test.go \
   $SRC/helm/pkg/kube/ready_fuzz.go

mv $SRC/cncf-fuzzing/projects/helm/provenance_fuzzer.go \
   $SRC/helm/pkg/provenance/

mv $SRC/cncf-fuzzing/projects/helm/storage_fuzzer.go \
   $SRC/helm/pkg/storage/

mv $SRC/cncf-fuzzing/projects/helm/releaseutil_fuzzer.go \
   $SRC/helm/pkg/release/util/

mv $SRC/cncf-fuzzing/projects/helm/lint_fuzzer.go \
   $SRC/helm/pkg/lint/

mv $SRC/cncf-fuzzing/projects/helm/resolver_fuzzer.go \
   $SRC/helm/internal/resolver/

mv $SRC/cncf-fuzzing/projects/helm/ignore_fuzzer_test.go \
   $SRC/helm/pkg/ignore/

cd $SRC/helm
printf "package ignore\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > pkg/ignore/register_fuzz_pkg.go
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod download && go mod tidy
compile_native_go_fuzzer helm.sh/helm/v4/pkg/ignore FuzzIgnoreParse fuzz_ignore_parse
compile_native_go_fuzzer helm.sh/helm/v4/pkg/strvals FuzzParse fuzz_strvals_parse
compile_go_fuzzer helm.sh/helm/v4/internal/resolver FuzzResolve fuzz_resolve
compile_go_fuzzer helm.sh/helm/v4/pkg/lint FuzzLintAll fuzz_lint_all
compile_go_fuzzer helm.sh/helm/v4/pkg/release/util FuzzSplitManifests fuzz_split_manifests
compile_go_fuzzer helm.sh/helm/v4/pkg/storage FuzzStorage fuzz_storage
compile_go_fuzzer helm.sh/helm/v4/pkg/provenance FuzzNewFromFiles fuzz_new_from_files
compile_go_fuzzer helm.sh/helm/v4/pkg/provenance FuzzParseMessageBlock fuzz_parse_message_block
compile_go_fuzzer helm.sh/helm/v4/pkg/provenance FuzzMessageBlock fuzz_message_block
compile_go_fuzzer helm.sh/helm/v4/pkg/kube FuzzKubeClient fuzz_kube_client
compile_go_fuzzer helm.sh/helm/v4/pkg/plugin FuzzFindPlugins fuzz_find_plugins
compile_go_fuzzer helm.sh/helm/v4/pkg/plugin FuzzLoadAll fuzz_load_all
compile_go_fuzzer helm.sh/helm/v4/internal/third_party/dep/fs FuzzfixLongPath fuzz_fix_long_path
compile_go_fuzzer helm.sh/helm/v4/internal/third_party/dep/fs Fuzz_fixLongPath fuzz_fix_long_path_internal
compile_go_fuzzer helm.sh/helm/v4/internal/third_party/dep/fs FuzzCopyDir fuzz_copy_dir
compile_go_fuzzer helm.sh/helm/v4/pkg/storage/driver FuzzSqlDriver fuzz_sql_driver
compile_go_fuzzer helm.sh/helm/v4/pkg/storage/driver FuzzRecords fuzz_records
compile_go_fuzzer helm.sh/helm/v4/pkg/storage/driver FuzzSecrets fuzz_secrets
compile_go_fuzzer helm.sh/helm/v4/pkg/storage/driver FuzzMemory fuzz_memory
compile_go_fuzzer helm.sh/helm/v4/pkg/storage/driver FuzzCfgmaps fuzz_cfgmaps
compile_native_go_fuzzer helm.sh/helm/v4/pkg/chart/v2 FuzzMetadataValidate fuzz_metadata_validate
compile_native_go_fuzzer helm.sh/helm/v4/pkg/chart/v2 FuzzDependencyValidate fuzz_dependency_validate
compile_go_fuzzer helm.sh/helm/v4/pkg/engine FuzzEngineRender fuzz_engine_render
compile_go_fuzzer helm.sh/helm/v4/pkg/action FuzzActionRun fuzz_action_run
compile_go_fuzzer helm.sh/helm/v4/pkg/action FuzzDependencyList fuzz_dependency_list
compile_go_fuzzer helm.sh/helm/v4/pkg/action FuzzActionList fuzz_action_list
compile_go_fuzzer helm.sh/helm/v4/pkg/action FuzzActionUninstall fuzz_action_uninstall
compile_go_fuzzer helm.sh/helm/v4/pkg/chart/v2/loader FuzzLoadDir fuzz_load_dir
compile_go_fuzzer helm.sh/helm/v4/pkg/chart/v2/util FuzzProcessDependencies fuzz_process_dependencies
compile_go_fuzzer helm.sh/helm/v4/pkg/chart/v2/util FuzzIsChartDir fuzz_is_chart_dir
compile_go_fuzzer helm.sh/helm/v4/pkg/chart/v2/util FuzzExpandFile fuzz_expand_file
compile_go_fuzzer helm.sh/helm/v4/pkg/chart/v2/util FuzzCreateFrom fuzz_create_from
compile_go_fuzzer helm.sh/helm/v4/pkg/repo FuzzIndex fuzz_index
compile_go_fuzzer helm.sh/helm/v4/pkg/repo FuzzIndexDirectory fuzz_index_directory
compile_go_fuzzer helm.sh/helm/v4/pkg/repo FuzzDownloadIndexFile fuzz_download_index_file
compile_go_fuzzer helm.sh/helm/v4/pkg/repo FuzzRepoFileUtils fuzz_repo_file_utils
compile_go_fuzzer helm.sh/helm/v4/pkg/repo FuzzWriteFile fuzz_write_file

