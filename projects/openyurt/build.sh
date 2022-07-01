#!/bin/bash -eu
# set -o nounset
# set -o pipefail
# set -o errexit
# set -x

PROJECT_ROOT="${GOPATH:-/root/go}/src/github.com/openyurtio"

# Build the fuzzers for all cloned sub-projects 
find "${PROJECT_ROOT}/" -type f -name oss_fuzz_build.sh | xargs chmod +x

find "${PROJECT_ROOT}/" -type f -name oss_fuzz_build.sh | bash -e
