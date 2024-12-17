# Copyright 2022 ADA Logics Ltd
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
################################################################################

# This line disturbs the fuzzer in the RunPodSandbox call. We are deliberately
# creating a context with a low deadline to avoid a timeout. This line will then
# not clean up all created resources because the return error is a context error.
# We rewrite the line instead of deleting it to maintain correct line numbers.
sed 's/if retErr == nil || isContextError(retErr) /if false /g' -i $SRC/cri-o/server/sandbox_run_linux.go

sed -i '1,2d' $SRC/cri-o/internal/config/cnimgr/cnimgr_test_inject.go
sed -i '1,2d' $SRC/cri-o/pkg/config/config_test_inject.go
sed -i '1,2d' $SRC/cri-o/server/server_test_inject.go
sed -i '1,2d' $SRC/cri-o/internal/lib/container_server_test_inject.go

cd $SRC
git clone --depth 1 git://git.gnupg.org/libgpg-error.git libgpg-error \
    && cd $SRC/libgpg-error \
    && sed -i 's/0.19/0.20/g' ./po/Makefile.in.in \
    && ./autogen.sh \
    && ./configure --disable-doc --enable-static --disable-shared \
    && make -j$(nproc) \
    && make install
cd $SRC
git clone --depth 1 git://git.gnupg.org/libassuan.git libassuan \
    && cd $SRC/libassuan \
    && ./autogen.sh \
    && ./configure --disable-doc --enable-static --disable-shared \
    && make -j$(nproc) \
    && make install
cd $SRC
git clone https://github.com/gpg/gpgme \
    && cd gpgme \
    && ./autogen.sh \
    && ./configure --enable-static --disable-shared --disable-doc \
    && make -j$(nproc) \
    && make install
#exit 0
cd $SRC/cri-o

make BUILDTAGS=""

mv $SRC/cncf-fuzzing/projects/cri-o/fuzz_server.go $SRC/cri-o/server/
go get github.com/AdaLogics/go-fuzz-headers@latest
make vendor

function compile_crio_fuzzer() {
    path=$1
    function=$2
    fuzzer=$3
    echo building $path $function $fuzzer
    tags=""
    # The coverage build will not work with the OSS-fuzz compile_go_fuzzer
    # because compile_go_fuzzer invokes "go mod tidy" which results in 
    # issues with dependencies. The coverage build part below is a modified
    # version of the coverage build in compile_go_fuzzer.
    if [ $SANITIZER == "coverage" ]; then
        # The tests cause issues with dependencies, so we remove all of them.

        fuzzed_package=`go list $tags -f '{{.Name}}' $path`
        abspath=`go list $tags -f {{.Dir}} $path`
        cd $abspath
        cp $GOPATH/ossfuzz_coverage_runner.go ./"${function,,}"_test.go
        sed -i -e 's/FuzzFunction/'$function'/' ./"${function,,}"_test.go
        sed -i -e 's/mypackagebeingfuzzed/'$fuzzed_package'/' ./"${function,,}"_test.go
        sed -i -e 's/TestFuzzCorpus/Test'$function'Corpus/' ./"${function,,}"_test.go

        fuzzed_repo=$(go list $tags -f {{.Module}} "$path")
        abspath_repo=`go list -m $tags -f {{.Dir}} $fuzzed_repo || go list $tags -f {{.Dir}} $fuzzed_repo`
        # give equivalence to absolute paths in another file, as go test -cover uses golangish pkg.Dir
        echo "s=$fuzzed_repo"="$abspath_repo"= > $OUT/$fuzzer.gocovpath
        go test -run Test${function}Corpus -v $tags -coverpkg $fuzzed_repo/... -c -o $OUT/$fuzzer $path
    else
        go-fuzz -func ${function} -o ${fuzzer}.a $path
        # Link Go code ($fuzzer.a) with fuzzing engine to produce fuzz target binary.
        
        $CXX $CXXFLAGS $LIB_FUZZING_ENGINE ${fuzzer}.a  \
		    /src/LVM2.2.03.15/base/libbase.a \
		    /src/libassuan/src/.libs/libassuan.a \
                    /src/gpgme/src/.libs/libgpgme.a \
                    /src/libgpg-error/src/.libs/libgpg-error.a \
		    -o $OUT/$fuzzer
                    /src/LVM2.2.03.15/libdm/ioctl/libdevmapper.so
    fi

    mkdir -p $OUT/lib
    cp /src/LVM2.2.03.15/libdm/ioctl/libdevmapper.so.1.02 $OUT/lib/
    cp /usr/lib/x86_64-linux-gnu/libdevmapper-event.so.1.02.1 $OUT/lib/
    cp /usr/lib/x86_64-linux-gnu/libdevmapper.so.1.02.1 $OUT/lib/
    cp /src/LVM2.2.03.15/libdm/ioctl/libdevmapper.so $OUT/lib/
    cp /usr/lib/x86_64-linux-gnu/libgpgme.so.11 $OUT/lib/
    cp /usr/lib/x86_64-linux-gnu/libgpgme.so $OUT/lib/
    cp /usr/lib/x86_64-linux-gnu/libassuan.so.0 $OUT/lib/
    cp /usr/lib/x86_64-linux-gnu/libassuan.so $OUT/lib/
    patchelf --set-rpath '$ORIGIN/lib' $OUT/$fuzzer
}
#sed 's/const sleepTimeBeforeCleanup = 1 \* time\.Minute/const sleepTimeBeforeCleanup = 1 \* time\.Nanosecond/g' -i ./internal/resourcestore/resourcestore.go
find $SRC/cri-o/server -name "*_test.go" -exec rm -rf {} \;
compile_crio_fuzzer github.com/cri-o/cri-o/server FuzzServer fuzz_server
compile_crio_fuzzer github.com/cri-o/cri-o/server FuzzServerLogSAN fuzz_server_logsan

cp $SRC/cncf-fuzzing/projects/cri-o/server_fuzzer2.go $SRC/cri-o/server/
compile_crio_fuzzer github.com/cri-o/cri-o/server FuzzgetDecryptionKeys fuzz_get_decryption_keys
compile_crio_fuzzer github.com/cri-o/cri-o/server FuzzIdtoolsParseIDMap fuzz_idtools_parse_id_map


mv $SRC/cncf-fuzzing/projects/cri-o/storage_fuzzer.go \
    $SRC/cri-o/internal/storage/
compile_crio_fuzzer github.com/cri-o/cri-o/internal/storage FuzzParseImageName fuzz_parse_image_name
compile_crio_fuzzer github.com/cri-o/cri-o/internal/storage FuzzShortnamesResolve fuzz_shortnames_resolve

mv $SRC/cncf-fuzzing/projects/cri-o/storage_fuzzer2.go \
    $SRC/cri-o/internal/storage/
compile_crio_fuzzer github.com/cri-o/cri-o/internal/storage Fuzz fuzz_copy_image

cp $SRC/cncf-fuzzing/projects/cri-o/utils_fuzzer.go $SRC/cri-o/utils/
compile_crio_fuzzer github.com/cri-o/cri-o/utils FuzzGeneratePasswd fuzz_generate_passwd


##
mv $SRC/cncf-fuzzing/projects/cri-o/util/mock_helpers_test.go $SRC/cri-o/test/mocks/containerstorage/mock_helpers_fuzz.go
cp $SRC/cncf-fuzzing/projects/cri-o/ParseStoreReference_fuzzer.go $SRC/cri-o/test/mocks/containerstorage/
compile_crio_fuzzer github.com/cri-o/cri-o/test/mocks/containerstorage FuzzParseStoreReference fuzz_parse_store_reference
##

cp $SRC/cncf-fuzzing/projects/cri-o/config_apparmor_fuzzer.go $SRC/cri-o/internal/config/apparmor/config_apparmor_fuzzer.go
compile_crio_fuzzer github.com/cri-o/cri-o/internal/config/apparmor FuzzLoadConfig fuzz_apparmor

cp $SRC/cncf-fuzzing/projects/cri-o/config_blockio_fuzzer.go $SRC/cri-o/internal/config/blockio/config_blockio_fuzzer.go
compile_crio_fuzzer github.com/cri-o/cri-o/internal/config/blockio FuzzLoadConfig fuzz_blockio

cp $SRC/cncf-fuzzing/projects/cri-o/config_rdt_fuzzer.go $SRC/cri-o/internal/config/rdt/config_rdt_fuzzer.go
compile_crio_fuzzer github.com/cri-o/cri-o/internal/config/rdt FuzzLoadConfig fuzz_rdt

cp $SRC/cncf-fuzzing/projects/cri-o/config_fuzzer.go $SRC/cri-o/pkg/config/config_fuzzer.go
compile_crio_fuzzer github.com/cri-o/cri-o/pkg/config FuzzLoadConfig fuzz_config

cp $SRC/cncf-fuzzing/projects/cri-o/container_fuzzer.go $SRC/cri-o/internal/factory/container/container_fuzzer.go
compile_crio_fuzzer github.com/cri-o/cri-o/internal/factory/container FuzzContainer fuzz_container

cp $SRC/cncf-fuzzing/projects/cri-o/container_server_fuzzer.go $SRC/cri-o/internal/lib/container_server_fuzzer.go
compile_crio_fuzzer github.com/cri-o/cri-o/internal/lib FuzzContainerServer fuzz_container_server

# dictionaries
mv $SRC/cncf-fuzzing/projects/cri-o/dicts/* $OUT/
