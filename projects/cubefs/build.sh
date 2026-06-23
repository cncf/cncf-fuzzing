set -o nounset
set -o pipefail
set -o errexit
set -x

# ============================================================
# 1. 复制 fuzzer 文件到 cubefs 对应目录
# ============================================================

mv $SRC/cncf-fuzzing/projects/cubefs/fuzz_master.go $SRC/cubefs/master/

# ============================================================
# 2. 准备 Go 模块（在 cubefs 目录下执行）
# ============================================================
go mod tidy -compat=1.17
go mod vendor
go get github.com/AdaLogics/go-fuzz-headers

# ============================================================
# 3. 加载 CGO 环境
# ============================================================
source $SRC/cubefs/build/cgo_env.sh

# ============================================================
# 4. 编译 master fuzzers（手动链接方式）
# ============================================================
cd $SRC/cubefs

# FuzzCreateVol
go-fuzz -tags gofuzz -func FuzzCreateVol -o fuzz_create_vol.a github.com/cubefs/cubefs/master
$CXX $CXXFLAGS -fsanitize=fuzzer \
    fuzz_create_vol.a \
    -L/src/cubefs/build/lib \
    -lrocksdb -lz -lbz2 -lsnappy -llz4 -lzstd -lc++ \
    -lresolv \
    -lpthread -ldl \
    -o $OUT/fuzz_create_vol

# FuzzNewMetaNode
go-fuzz -tags gofuzz -func FuzzNewMetaNode -o fuzz_new_metanode.a github.com/cubefs/cubefs/master
$CXX $CXXFLAGS -fsanitize=fuzzer \
    fuzz_new_metanode.a \
    -L/src/cubefs/build/lib \
    -lrocksdb -lz -lbz2 -lsnappy -llz4 -lzstd -lc++ \
    -lresolv \
    -lpthread -ldl \
    -o $OUT/fuzz_new_metanode

# ============================================================
# 5. 编译 metanode fuzzers
# ============================================================
mv $SRC/cncf-fuzzing/projects/cubefs/fuzz_metanode.go $SRC/cubefs/metanode/

cd $SRC/cubefs
go-fuzz -tags gofuzz -func FuzzNewInode -o fuzz_new_inode.a github.com/cubefs/cubefs/metanode
$CXX $CXXFLAGS -fsanitize=fuzzer \
    fuzz_new_inode.a \
    -L/src/cubefs/build/lib \
    -lrocksdb -lz -lbz2 -lsnappy -llz4 -lzstd -lc++ \
    -lresolv \
    -lpthread -ldl \
    -o $OUT/fuzz_new_inode

go-fuzz -tags gofuzz -func FuzzNewExtend -o fuzz_new_extend.a github.com/cubefs/cubefs/metanode
$CXX $CXXFLAGS -fsanitize=fuzzer \
    fuzz_new_extend.a \
    -L/src/cubefs/build/lib \
    -lrocksdb -lz -lbz2 -lsnappy -llz4 -lzstd -lc++ \
    -lresolv \
    -lpthread -ldl \
    -o $OUT/fuzz_new_extend

# ============================================================
# 6. 编译 datanode fuzzer
# ============================================================
mv $SRC/cncf-fuzzing/projects/cubefs/fuzz_datanode.go $SRC/cubefs/datanode/

cd $SRC/cubefs
go-fuzz -tags gofuzz -func FuzzNewDisk -o fuzz_new_disk.a github.com/cubefs/cubefs/datanode
$CXX $CXXFLAGS -fsanitize=fuzzer \
    fuzz_new_disk.a \
    -L/src/cubefs/build/lib \
    -lrocksdb -lz -lbz2 -lsnappy -llz4 -lzstd -lc++ \
    -lresolv \
    -lpthread -ldl \
    -o $OUT/fuzz_new_disk

# ============================================================
# 7. 编译 client fuzzer
# ============================================================
mv $SRC/cncf-fuzzing/projects/cubefs/fuzz_client.go $SRC/cubefs/client/fs/

cd $SRC/cubefs
go-fuzz -tags gofuzz -func FuzzNewFile -o fuzz_new_file.a github.com/cubefs/cubefs/client/fs
$CXX $CXXFLAGS -fsanitize=fuzzer \
    fuzz_new_file.a \
    -L/src/cubefs/build/lib \
    -lrocksdb -lz -lbz2 -lsnappy -llz4 -lzstd -lc++ \
    -lresolv \
    -lpthread -ldl \
    -o $OUT/fuzz_new_file

# ============================================================
# 8. 编译 sdk fuzzer
# ============================================================
mv $SRC/cncf-fuzzing/projects/cubefs/fuzz_sdk.go $SRC/cubefs/sdk/meta/

cd $SRC/cubefs
go-fuzz -tags gofuzz -func FuzzNewMeta -o fuzz_new_meta.a github.com/cubefs/cubefs/sdk/meta
$CXX $CXXFLAGS -fsanitize=fuzzer \
    fuzz_new_meta.a \
    -L/src/cubefs/build/lib \
    -lrocksdb -lz -lbz2 -lsnappy -llz4 -lzstd -lc++ \
    -lresolv \
    -lpthread -ldl \
    -o $OUT/fuzz_new_meta

echo "All fuzzers built successfully!"
