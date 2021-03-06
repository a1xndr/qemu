#!/bin/sh
#
# OSS-Fuzz build script. See:
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#buildsh
#
# The file is consumed by:
# https://github.com/google/oss-fuzz/blob/master/projects/qemu/Dockerfiles
#
# This code is licensed under the GPL version 2 or later.  See
# the COPYING file in the top-level directory.
#

# build project
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \
#     $LIB_FUZZING_ENGINE /path/to/library.a

# There seems to be a bug in clang-11 (used for builds on oss-fuzz) :
#   accel/tcg/cputlb.o: In function `load_memop':
#   accel/tcg/cputlb.c:1505: undefined reference to `qemu_build_not_reached'
#
# When building with optimization, the compiler is expected to prove that the
# statement cannot be reached, and remove it. For some reason clang-11 doesn't
# remove it, resulting in an unresolved reference to qemu_build_not_reached
# Undefine the __OPTIMIZE__ macro which compiler.h relies on to choose whether
# to " #define qemu_build_not_reached()  g_assert_not_reached() "
EXTRA_CFLAGS="$CFLAGS -U __OPTIMIZE__"

if ! { [ -e "./COPYING" ] &&
   [ -e "./MAINTAINERS" ] &&
   [ -e "./Makefile" ] &&
   [ -e "./docs" ] &&
   [ -e "./VERSION" ] &&
   [ -e "./linux-user" ] &&
   [ -e "./softmmu" ];} ; then
    echo "Please run the script from the top of the QEMU tree"
    exit
fi

mkdir -p "./build-oss-fuzz/"
cd "./build-oss-fuzz/" || exit


if [ -z ${LIB_FUZZING_ENGINE+x} ]; then
    LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
fi

if [ -z ${OUT+x} ]; then
    DEST_DIR=$(realpath "./DEST_DIR")
else
    DEST_DIR=$OUT
fi

mkdir -p "$DEST_DIR/lib/"  # Copy the shared libraries here

# Build once to get the list of dynamic lib paths, and copy them over
../configure --disable-werror --cc="$CC" --cxx="$CXX" \
    --extra-cflags="$EXTRA_CFLAGS"

if ! make CONFIG_FUZZ=y CFLAGS="$LIB_FUZZING_ENGINE" "-j$(nproc)" \
    i386-softmmu/fuzz; then
    echo  "Build failed. Please specify a compiler with fuzzing support"\
          "using the \$CC and \$CXX environemnt variables, or specify a"\
          "\$LIB_FUZZING_ENGINE compatible with your compiler"
    echo  "For example: CC=clang CXX=clang++ $0"
    exit 0
fi

for i in $(ldd ./i386-softmmu/qemu-fuzz-i386 | cut -f3 -d' '); do 
    cp "$i" "$DEST_DIR/lib/"
done
rm ./i386-softmmu/qemu-fuzz-i386

# Build a second time to build the final binary with correct rpath
../configure --bindir="$DEST_DIR" --datadir="$DEST_DIR/data/" --disable-werror \
    --cc="$CC" --cxx="$CXX" --extra-cflags="$EXTRA_CFLAGS" \
    --extra-ldflags="-Wl,-rpath,'\$\$ORIGIN/lib'"
make CONFIG_FUZZ=y CFLAGS="$LIB_FUZZING_ENGINE" "-j$(nproc)" i386-softmmu/fuzz

# Copy over the datadir
cp  -r ../pc-bios/ "$DEST_DIR/pc-bios"

# Run the fuzzer with no arguments, to print the help-string and get the list
# of available fuzz-targets. Copy over the qemu-fuzz-i386, naming it according
# to each available fuzz target (See 05509c8e6d fuzz: select fuzz target using
# executable name)
for target in $(./i386-softmmu/qemu-fuzz-i386 | awk '$1 ~ /\*/  {print $2}');
do
    cp ./i386-softmmu/qemu-fuzz-i386 "$DEST_DIR/qemu-fuzz-i386-target-$target"
done

echo "Done. The fuzzers are located in $DEST_DIR"
