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

go mod download && go mod tidy
compile_go_fuzzer helm.sh/helm/v3/internal/third_party/dep/fs FuzzfixLongPath fuzz_fix_long_path
compile_go_fuzzer helm.sh/helm/v3/pkg/chart FuzzMetadataValidate fuzz_metadata_validate
compile_go_fuzzer helm.sh/helm/v3/pkg/chart FuzzDependencyValidate fuzz_dependency_validate
compile_go_fuzzer helm.sh/helm/v3/pkg/engine FuzzEngineRender fuzz_engine_render


sed 's/go 1.16/go 1.18/g' -i $SRC/helm/go.mod

mv $SRC/cncf-fuzzing/projects/helm/strvals_fuzzer_test.go \
   $SRC/helm/pkg/strvals/

mv $SRC/cncf-fuzzing/projects/helm/ignore_fuzzer_test.go \
   $SRC/helm/internal/ignore/

gotip mod download && gotip mod tidy
gotip get github.com/AdamKorcz/go-118-fuzz-build/utils
compile_native_go_fuzzer helm.sh/helm/v3/internal/ignore FuzzIgnoreParse fuzz_ignore_parse
compile_native_go_fuzzer helm.sh/helm/v3/pkg/strvals FuzzStrvalsParse fuzz_strvals_parse