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

go get github.com/AdaLogics/go-fuzz-headers

mv $SRC/containerd/content/local/store_test.go \
	$SRC/containerd/content/local/store_test_fuzz.go
mv $SRC/cncf-fuzzing/projects/containerd/content_local_fuzzer.go \
	$SRC/containerd/content/local/


mv $SRC/cncf-fuzzing/projects/containerd/docker_fuzzer_internal.go $SRC/containerd/remotes/docker/config/
compile_go_fuzzer github.com/containerd/containerd/remotes/docker/config FuzzParseHostsFile fuzz_parser_hosts_file

#sed 's/package main/package main2/g' -i $SRC/containerd/cmd/containerd/main.go
#sed 's/func main/func main2/g' -i $SRC/containerd/cmd/containerd/main.go

#mv $SRC/cncf-fuzzing/projects/containerd/containerd_import_structured_fuzzer.go \
#	$SRC/containerd/contrib/fuzz/
#compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzContainerdImportStructured fuzz_containerd_import_structured
rm $SRC/cncf-fuzzing/projects/containerd/containerd_import_structured_fuzzer.go

mv $SRC/cncf-fuzzing/projects/containerd/apparmor_fuzzer.go $SRC/containerd/contrib/apparmor/
compile_go_fuzzer github.com/containerd/containerd/contrib/apparmor FuzzLoadDefaultProfile fuzz_load_default_profile

mv $SRC/cncf-fuzzing/projects/containerd/compression_fuzzer.go $SRC/containerd/archive/compression/
compile_go_fuzzer github.com/containerd/containerd/archive/compression FuzzDecompressStream fuzz_decompress_stream

mv $SRC/cncf-fuzzing/projects/containerd/*.go $SRC/containerd/contrib/fuzz/
compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzImagesCheck fuzz_images_check
compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzExchange fuzz_diff_compare
compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzDiffCompare fuzz_diff_compare
compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzDiffApply fuzz_diff_apply
compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzUUIDParse fuzz_uuid_parse
