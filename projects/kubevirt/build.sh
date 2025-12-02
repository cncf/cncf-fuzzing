#!/bin/bash -eu

# Build script for kubevirt OSS-Fuzz integration

# Download and install Go 1.25.4
GO_VERSION="1.25.4"
curl -LO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
rm -rf /usr/local/go
tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
rm "go${GO_VERSION}.linux-amd64.tar.gz"
export PATH=/usr/local/go/bin:$PATH
export GOROOT=/usr/local/go
go version

# Build go-118-fuzz-build from source (branch v2_2)
cd $SRC/go-118-fuzz-build
go build -o $GOPATH/bin/go-118-fuzz-build .

cd $SRC/kubevirt

# Reference to the cncf-fuzzing directory
CNCF_KUBEVIRT="$SRC/cncf-fuzzing/projects/kubevirt"

# Create all fuzzer directories
mkdir -p pkg/virt-controller/watch/pool/fuzz
mkdir -p pkg/virt-controller/watch/vm/fuzz
mkdir -p pkg/virt-controller/watch/vmi/fuzz
mkdir -p pkg/virt-controller/watch/node/fuzz
mkdir -p pkg/virt-controller/watch/migration/fuzz
mkdir -p pkg/virt-controller/watch/clone/fuzz
mkdir -p pkg/virt-controller/watch/dra/fuzz
mkdir -p pkg/virt-controller/watch/replicaset/fuzz
mkdir -p pkg/virt-controller/watch/workload-updater/fuzz
mkdir -p pkg/virt-controller/watch/drain/evacuation/fuzz
mkdir -p pkg/virt-controller/watch/drain/disruptionbudget/fuzz
mkdir -p pkg/virt-controller/watch/testutils
mkdir -p pkg/virt-operator/resource/apply/fuzz
mkdir -p pkg/virt-operator/resource/generate/install/fuzz
mkdir -p pkg/virt-handler/hotplug-disk/fuzz
mkdir -p pkg/host-disk/fuzz
mkdir -p pkg/virt-api/webhooks/fuzz
mkdir -p pkg/virt-api/webhooks/mutating-webhook
mkdir -p pkg/virt-api/webhooks/validating-webhook

# Copy helper files
cp "$CNCF_KUBEVIRT/fuzz_helpers.go" pkg/virt-controller/watch/testutils/fuzz_helpers.go
cp "$CNCF_KUBEVIRT/clone_utils_fuzz.go" pkg/virt-controller/watch/clone/utils_fuzz.go

# Copy noop validator for fuzzing (avoids 111s OpenAPI initialization)
cp "$CNCF_KUBEVIRT/validator_fuzz.go" pkg/virt-api/definitions/validator_fuzz.go

# Add build tag to validator.go to exclude it when using gofuzz_libfuzzer
sed -i '1i//go:build !gofuzz_libfuzzer\n' pkg/virt-api/definitions/validator.go

# Copy utility files that expose private controller fields
cp "$CNCF_KUBEVIRT/pool_util.go" pkg/virt-controller/watch/pool/util.go
cp "$CNCF_KUBEVIRT/vm_updatereactor.go" pkg/virt-controller/watch/vm/updatereactor.go
cp "$CNCF_KUBEVIRT/vm_patchreactor.go" pkg/virt-controller/watch/vm/patchreactor.go
cp "$CNCF_KUBEVIRT/node_util.go" pkg/virt-controller/watch/node/util.go

# Copy virt-controller fuzzers
cp "$CNCF_KUBEVIRT/pool_fuzz_test.go" pkg/virt-controller/watch/pool/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/vm_fuzz_test.go" pkg/virt-controller/watch/vm/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/vmi_fuzz_test.go" pkg/virt-controller/watch/vmi/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/node_fuzz_test.go" pkg/virt-controller/watch/node/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/migration_fuzz_test.go" pkg/virt-controller/watch/migration/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/clone_fuzz_test.go" pkg/virt-controller/watch/clone/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/dra_fuzz_test.go" pkg/virt-controller/watch/dra/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/replicaset_fuzz_test.go" pkg/virt-controller/watch/replicaset/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/workload_updater_fuzz_test.go" pkg/virt-controller/watch/workload-updater/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/evacuation_fuzz_test.go" pkg/virt-controller/watch/drain/evacuation/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/disruptionbudget_fuzz_test.go" pkg/virt-controller/watch/drain/disruptionbudget/fuzz/fuzz_test.go

# Copy virt-operator fuzzers
cp "$CNCF_KUBEVIRT/apply_fuzz_test.go" pkg/virt-operator/resource/apply/fuzz/fuzz_test.go
cp "$CNCF_KUBEVIRT/install_fuzz_test.go" pkg/virt-operator/resource/generate/install/fuzz/fuzz_test.go

# Copy virt-handler fuzzer
cp "$CNCF_KUBEVIRT/hotplug_disk_fuzz_test.go" pkg/virt-handler/hotplug-disk/fuzz/fuzz_test.go

# Copy host-disk fuzzer
cp "$CNCF_KUBEVIRT/host_disk_fuzz_test.go" pkg/host-disk/fuzz/fuzz_test.go

# Copy virt-api webhook fuzzers (not FuzzAdmitter)
cp "$CNCF_KUBEVIRT/mutating_webhook_fuzz_test.go" pkg/virt-api/webhooks/mutating-webhook/fuzz_test.go
cp "$CNCF_KUBEVIRT/validating_webhook_fuzz_test.go" pkg/virt-api/webhooks/validating-webhook/fuzz_test.go

# Copy modified FuzzAdmitter (with timeout check removed and nil pointer fixes for OSS-Fuzz)
# Using go-fuzz-headers version for better performance
cp "$CNCF_KUBEVIRT/fuzz_admitter_gofuzzheaders_test.go" pkg/virt-api/webhooks/fuzz/fuzz_test.go

# Just need to remove the conflicting test suite file
rm -f pkg/virt-api/webhooks/fuzz/fuzz_suite_test.go

# Disable workspace mode to allow normal Go module resolution
# Use readonly mode which will work with available modules
# Disable VCS stamping since we're in a Docker container
export GOWORK=off
#export GOFLAGS="-mod=readonly -buildvcs=false"
export GOFLAGS="-mod=readonly -buildvcs=false -tags=gofuzz_libfuzzer"


# Remove conflicting test suite files from all fuzzer directories
rm -f pkg/virt-controller/watch/pool/fuzz/fuzz_suite_test.go
rm -f pkg/virt-controller/watch/vm/fuzz/fuzz_suite_test.go
rm -f pkg/virt-controller/watch/vmi/fuzz/fuzz_suite_test.go
rm -f pkg/virt-controller/watch/node/fuzz/fuzz_suite_test.go
rm -f pkg/virt-controller/watch/migration/fuzz/fuzz_suite_test.go
rm -f pkg/virt-controller/watch/clone/fuzz/fuzz_suite_test.go
rm -f pkg/virt-controller/watch/dra/fuzz/fuzz_suite_test.go
rm -f pkg/virt-controller/watch/replicaset/fuzz/fuzz_suite_test.go
rm -f pkg/virt-controller/watch/workload-updater/fuzz/fuzz_suite_test.go
rm -f pkg/virt-controller/watch/drain/evacuation/fuzz/fuzz_suite_test.go
rm -f pkg/virt-controller/watch/drain/disruptionbudget/fuzz/fuzz_suite_test.go
rm -f pkg/virt-operator/resource/apply/fuzz/fuzz_suite_test.go
rm -f pkg/virt-operator/resource/generate/install/fuzz/fuzz_suite_test.go

# Add go-fuzz-headers replace directive
go mod edit -replace=github.com/AdaLogics/go-fuzz-headers=$SRC/go-fuzz-headers
go mod tidy

# Build virt-controller fuzzers
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/pool/fuzz FuzzExecute FuzzPoolExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/vm/fuzz FuzzExecute FuzzVMExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/vmi/fuzz FuzzExecute FuzzVMIExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/node/fuzz FuzzExecute FuzzNodeExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/migration/fuzz FuzzExecute FuzzMigrationExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/clone/fuzz FuzzVMCloneController FuzzVMCloneController
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/dra/fuzz FuzzExecute FuzzDRAExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/replicaset/fuzz FuzzReplicaSetController FuzzReplicaSetController
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/workload-updater/fuzz FuzzWorkloadUpdateController FuzzWorkloadUpdateController
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/drain/evacuation/fuzz FuzzExecute FuzzEvacuationExecute
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-controller/watch/drain/disruptionbudget/fuzz FuzzExecute FuzzDisruptionBudgetExecute

# Build virt-operator fuzzers
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-operator/resource/apply/fuzz FuzzReconciler FuzzReconciler
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-operator/resource/generate/install/fuzz FuzzLoadInstallStrategyFromCache FuzzLoadInstallStrategyFromCache

# Build virt-handler fuzzers
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-handler/hotplug-disk/fuzz FuzzHotplugVolumeMounting FuzzHotplugVolumeMounting
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-handler/hotplug-disk/fuzz FuzzHotplugOwnershipValidation FuzzHotplugOwnershipValidation
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-handler/hotplug-disk/fuzz FuzzHotplugDeviceCreation FuzzHotplugDeviceCreation
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-handler/hotplug-disk/fuzz FuzzHotplugVolumeSourceValidation FuzzHotplugVolumeSourceValidation
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-handler/hotplug-disk/fuzz FuzzHotplugVMIVolumeStatus FuzzHotplugVMIVolumeStatus
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-handler/hotplug-disk/fuzz FuzzHotplugMountRecord FuzzHotplugMountRecord

# Build host-disk fuzzers
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/host-disk/fuzz FuzzHostDiskSymlinkContainment FuzzHostDiskSymlinkContainment
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/host-disk/fuzz FuzzHostDiskOwnershipValidation FuzzHostDiskOwnershipValidation
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/host-disk/fuzz FuzzPVCDiskSymlinkEscape FuzzPVCDiskSymlinkEscape

# Build webhook fuzzers
#compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-api/webhooks/mutating-webhook FuzzWebhookMutators FuzzWebhookMutators
#compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-api/webhooks/validating-webhook FuzzWebhookAdmitters FuzzWebhookAdmitters

# Build FuzzAdmitter with compile_native_go_fuzzer_v2 (no longer needs -preserve thanks to no-op validator)
compile_native_go_fuzzer_v2 kubevirt.io/kubevirt/pkg/virt-api/webhooks/fuzz FuzzAdmitterFast FuzzAdmitter

