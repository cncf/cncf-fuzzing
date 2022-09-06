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

compile_go_fuzzer github.com/containerd/containerd/remotes/docker/config FuzzParseHostsFile fuzz_parser_hosts_file

compile_go_fuzzer github.com/containerd/containerd/contrib/apparmor FuzzLoadDefaultProfile fuzz_load_default_profile

compile_go_fuzzer github.com/containerd/containerd/archive/compression FuzzDecompressStream fuzz_decompress_stream

compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzImagesCheck fuzz_images_check
compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzExchange fuzz_diff_compare
compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzDiffCompare fuzz_diff_compare
compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzDiffApply fuzz_diff_apply
compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzUUIDParse fuzz_uuid_parse
compile_go_fuzzer github.com/containerd/containerd/contrib/fuzz FuzzContainerdImport fuzz_containerd_import
