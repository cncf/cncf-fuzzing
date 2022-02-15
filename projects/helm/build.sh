#!/bin/bash -eu
set -o nounset
set -o pipefail
set -o errexit
set -x

mv $SRC/cncf-fuzzing/projects/helm/strvals_fuzzer_test.go \
   $SRC/helm/pkg/strvals/

mv $SRC/cncf-fuzzing/projects/helm/ignore_fuzzer_test.go \
   $SRC/helm/internal/ignore/


sed 's/go 1.16/go 1.18/g' -i $SRC/helm/go.mod

gotip mod download && gotip mod tidy
gotip get github.com/AdamKorcz/go-118-fuzz-build/utils
compile_native_go_fuzzer helm.sh/helm/v3/internal/ignore FuzzIgnoreParse fuzz_ignore_parse
compile_native_go_fuzzer helm.sh/helm/v3/pkg/strvals FuzzStrvalsParse fuzz_strvals_parse
