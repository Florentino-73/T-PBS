
set -x

srcdir=`dirname $0`
[ -z "$srcdir" ] && srcdir=.

ORIGDIR=`pwd`
cd $srcdir

#autoreconf -v --install || exit $?
#cd $ORIGDIR             || exit $?

if [ "$1" = "DEBUG" ] 
then
    COMMON_FLAGS="-ggdb -Og"
else
    COMMON_FLAGS="-g -O2"
fi

#thkim
linux_sgx_dir="${SGX_SDK:-/opt/intel/sgxsdk}"


COMMON_FLAGS="$COMMON_FLAGS -DNO_HEAP_CHECK -DTCMALLOC_SGX -DTCMALLOC_NO_ALIASES -fstack-protector"

ENCLAVE_CFLAGS="$COMMON_FLAGS -ffreestanding -nostdinc -fvisibility=hidden -fPIC"
ENCLAVE_CXXFLAGS="$ENCLAVE_CFLAGS -nostdinc++"
CFLAGS="$CFLAGS $ENCLAVE_CFLAGS"
CXXFLAGS="$CXXFLAGS $ENCLAVE_CXXFLAGS"
#CPPFLAGS="-I../../../common/inc -I../../../common/inc/tlibc -I../../../common/inc/internal/ -I../../../sdk/tlibcxx/stlport -I../../../sdk/trts/"
# CPPFLAGS="-I$linux_sgx_dir/common/inc -I$linux_sgx_dir/common/inc/tlibc -I$linux_sgx_dir/common/inc/internal/ -I$linux_sgx_dir/sdk/tlibcxx/stlport -I$linux_sgx_dir/sdk/trts/"
CPPFLAGS="-I$linux_sgx_dir/common/inc -I$linux_sgx_dir/common/inc/tlibc -I$linux_sgx_dir/common/inc/internal/ -I$linux_sgx_dir/sdk/tlibcxx -I$linux_sgx_dir/sdk/tlibcxx/include -I$linux_sgx_dir/sdk/trts/"

if echo $CFLAGS | grep -q -- '-m32'; then
   HOST_OPT='--host=i386-linux-gnu'
fi

export CFLAGS
export CXXFLAGS
export CPPFLAGS
$srcdir/configure $HOST_OPT --enable-shared=no \
   --disable-cpu-profiler \
   --disable-heap-profiler       \
   --disable-heap-checker \
   --disable-debugalloc \
   --enable-minimal

#must remove this attribute define in generated config.h, or can't debug tcmalloc with sgx-gdb
if [ "$1" = "DEBUG" ]
then
    sed -i 's/#define HAVE___ATTRIBUTE__ 1/\/\/#define HAVE___ATTRIBUTE__ 1/g' src/config.h
fi
