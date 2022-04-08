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
    && make \
    && make install
cd $SRC
git clone --depth 1 git://git.gnupg.org/libassuan.git libassuan \
    && cd $SRC/libassuan \
    && ./autogen.sh \
    && ./configure --disable-doc --enable-static --disable-shared \
    && make \
    && make install
cd $SRC
git clone https://github.com/gpg/gpgme \
    && cd gpgme \
    && ./autogen.sh \
    && ./configure --enable-static --disable-shared --disable-doc \
    && make \
    && make install
cd $SRC/cri-o

apt-get update -qq && apt-get install -y \
  libbtrfs-dev \
  git \
  libassuan-dev \
  libdevmapper-dev \
  libglib2.0-dev \
  libc6-dev \
  libgpgme-dev \
  libgpg-error-dev \
  libseccomp-dev \
  libsystemd-dev \
  libselinux1-dev \
  pkg-config \
  go-md2man \
  libudev-dev \
  software-properties-common
make BUILDTAGS=""

mv $SRC/cncf-fuzzing/projects/cri-o/fuzz_server.go $SRC/cri-o/server/
go get github.com/AdaLogics/go-fuzz-headers@f1761e18c0c6d721973fbe338aa87dcd60e11c41
make vendor
go-fuzz -func FuzzServer -o fuzz_server.a github.com/cri-o/cri-o/server

# Link Go code ($fuzzer.a) with fuzzing engine to produce fuzz target binary.
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_server.a \
        /src/LVM2.2.03.15/libdm/ioctl/libdevmapper.a \
        /src/gpgme/src/.libs/libgpgme.a \
        /src/libgpg-error/src/.libs/libgpg-error.a \
        /src/LVM2.2.03.15/base/libbase.a \
        /src/libassuan/src/.libs/libassuan.a \
        -o $OUT/server_fuzzer