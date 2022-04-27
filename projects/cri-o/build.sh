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
cd $SRC/cri-o

make BUILDTAGS=""

mv $SRC/cncf-fuzzing/projects/cri-o/fuzz_server.go $SRC/cri-o/server/
go get github.com/AdaLogics/go-fuzz-headers@53b129c8971380abe6fc1812bd8eb43105ed8867
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
        
        $CXX $CXXFLAGS $LIB_FUZZING_ENGINE ${fuzzer}.a \
                    /src/LVM2.2.03.15/libdm/ioctl/libdevmapper.so \
                    /src/gpgme/src/.libs/libgpgme.a \
                    /src/libgpg-error/src/.libs/libgpg-error.a \
                    /src/LVM2.2.03.15/base/libbase.a \
                    /src/libassuan/src/.libs/libassuan.a \
                    -o $OUT/$fuzzer
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

mv $SRC/cncf-fuzzing/projects/cri-o/storage_fuzzer.go \
    $SRC/cri-o/internal/storage/
compile_crio_fuzzer github.com/cri-o/cri-o/internal/storage FuzzParseImageName fuzz_parse_image_name
compile_crio_fuzzer github.com/cri-o/cri-o/internal/storage FuzzShortnamesResolve fuzz_shortnames_resolve

cp $SRC/cncf-fuzzing/projects/cri-o/config_apparmor_fuzzer.go $SRC/cri-o/internal/config/apparmor/config_apparmor_fuzzer.go
compile_crio_fuzzer github.com/cri-o/cri-o/internal/config/apparmor FuzzLoadConfig fuzz_apparmor

cp $SRC/cncf-fuzzing/projects/cri-o/config_blockio_fuzzer.go $SRC/cri-o/internal/config/blockio/config_blockio_fuzzer.go
compile_crio_fuzzer github.com/cri-o/cri-o/internal/config/blockio FuzzLoadConfig fuzz_blockio

cp $SRC/cncf-fuzzing/projects/cri-o/config_rdt_fuzzer.go $SRC/cri-o/internal/config/rdt/config_rdt_fuzzer.go
compile_crio_fuzzer github.com/cri-o/cri-o/internal/config/rdt FuzzLoadConfig fuzz_rdt

# dictionaries
mv $SRC/cncf-fuzzing/projects/cri-o/dicts/* $OUT/
