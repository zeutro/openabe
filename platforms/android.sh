###############################################################################
# android-dependencies.sh
#
# This script implicitly documents the software dependencies, and current
# software versions, for our OpenABE android cross-compilation. Patches and
# modifications to software are found in this directory.
#
# Adjust the global environment variables for your specific system config. In
# particular, the Android NDK must be on your system so that we can build a
# standalone toolchain. You will use your toolchain to cross-compile a number
# of dependencies before building OpenABE. Some of this software needs to be
# patched to compile successfully.
#
# Example use:
# ./android-dependencies.sh /opt/android-ndk-r10e /home/userfoo/android
#
# Copy Flexlexer.h to /sysroot/usr
#
# Example use:
# ./android.sh /path/to/android/ndk/? 
# 
################################################################################

#!/bin/bash

# Specify software versions as globals in this script.
OPENSSL="openssl-1.1.1-dev"
RELIC="relic-toolkit-0.4.1h"
GTEST="googletest-release-1.8.0"
GMP="gmp-6.0.0a"
CWD=$PWD

# Specify the default compiler as clang++ or g++.

# Make a standalone toolchain that contains all cross compilation tools and a
# sysroot for linking cross-compiled libraries. Defaults are: --stl=gnustl,
# --system=linux-x86_64, platform=android-3. We will use platform=android-14
# but we could use 9 to cover those left with Android 2.3.
makeStandAloneToolChain()
{
    printf "Making standalone toolchain in $HOME/android\n"
    $ANDROID_NDK_ROOT/build/tools/make-standalone-toolchain.sh --toolchain=$TOOLCHAIN_ARCH --llvm-version=3.6 --platform=$MIN_PLATFORM --install-dir=$INSTALLDIR
}

# Check environment variables and command line arguments for build setup.
if [ -n "$ANDROID_NDK_ROOT" ]; then
    printf "ANDROID_NDK_ROOT=$ANDROID_NDK_ROOT\n"
elif [ -n "$1" ]; then
    printf "ANDROID_NDK_ROOT=$1\n"
    ANDROID_NDK_ROOT=$1
else
    printf "Android NDK Root not provided, exiting\n"
    exit 1
fi

# The user can supply either a maketoolchain option or a path to a built
# toolchain. The make option builds a standalone toolchain per the NDK.
if [ -n "$2" ]; then
    if [ "$2" == "maketoolchain" ]; then
        if [ -n "$3" ]; then
            if [ "$3" == "32" ]; then
                TOOLCHAIN_ARCH="arm-linux-androideabi-4.8"
                MIN_PLATFORM=android-14
                INSTALLDIR=$HOME/android
            elif [ "$3" == "64" ]; then
                TOOLCHAIN_ARCH="aarch64-linux-android-4.9"
                MIN_PLATFORM=android-21
                INSTALLDIR=$HOME/android64
            else
                printf "Provide either no arguments, 32, or 64 for the architecture, exiting\n"
                exit 1
            fi
        else
            # Same as the else 64 above.
            TOOLCHAIN_ARCH="aarch64-linux-android-4.9"
            MIN_PLATFORM=android-21
            INSTALLDIR=$HOME/android64
        fi

        makeStandAloneToolChain
        exit 1
    fi
    TOOLCHAIN=$2
else
    printf "maktoolchain option or android toolchain path not provided, exiting\n"
    exit 1
fi

# Check the toolchain architecture.
if [ -f "$TOOLCHAIN/bin/aarch64-linux-android-g++" ]; then
    printf "64-bit toolchain architecture\n"
    TOOLCHAIN_ARCH="aarch64-linux-android"
    MIN_ARCH="aarch64" # For boost.
    OARCH="linux-aarch64" # For OpenSSL.
    RARM="ARM" # For Relic.
    RDWORD="64"
elif [ -f "$TOOLCHAIN/bin/arm-linux-androideabi-g++" ]; then
    printf "32-bit toolchain architecture\n"
    TOOLCHAIN_ARCH="arm-linux-androideabi"
    MIN_ARCH="arm" # For boost.
    OARCH="android-armv7" # For OpenSSL.
    RARM="ARM" # For Relic.
    RDWORD="32"
else
    printf "Toolchain path provided doesn't contain a valid compiler, exiting\n"
fi

# The user can choose whether to compile with clang or gcc. Gold linker always used.
if [ -n "$3" ]; then
    if [ "$3" == "clang" ]; then
        printf "Setup for compilation with clang front-end\n"
        CPPCOMPILER="clang++"
        CCOMPILER="clang"
        AR="llvm-ar"
        AS="llvm-as"
        RANLIB="/bin/true"
        LD="$TOOLCHAIN_ARCH-ld"
    else
        printf "Incorrect option provided (specify clang or nothing), exiting\n"
        exit 1
    fi
else
    printf "Setup for compilation with gnu compiler\n"
    CPPCOMPILER="$TOOLCHAIN_ARCH-g++"
    CCOMPILER="$TOOLCHAIN_ARCH-gcc"
    AR="$TOOLCHAIN_ARCH-ar"
    AS="$TOOLCHAIN_ARCH-as"
    RANLIB="$TOOLCHAIN_ARCH-ranlib"
    LD="$TOOLCHAIN_ARCH-ld"
fi

# Specify some useful variables for subsequent dependency build functions.
SYSROOT=$TOOLCHAIN/sysroot/usr
PREF=$TOOLCHAIN/bin/
CWD=$PWD

# Export variables required by a few of the build functions.
export CC="$PREF$CCOMPILER"
export CXX="$PREF$CPPCOMPILER"
export LD="$PREF$LD"
export AS="$PREF$AS"
export RANLIB="$PREF$RANLIB"
export AR="$PREF$AR"
export CFLAGS="-I$SYSROOT/include --sysroot=$SYSROOT -I$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/4.8/include/"
export LDFLAGS="-L$SYSROOT/lib -L$ANDROID_NDK_ROOT/sources/cxx-stl/gnu-libstdc++/4.8/libs/armeabi/ -lgnustl_shared"

# Download and compile gmp. The only flag we have to include is --enable-cxx.
buildGMPForAndroid()
{
    printf "Building GMP\n"
    wget https://gmplib.org/download/gmp/$GMP.tar.lz
    sleep 1
    lzip -d $GMP.tar.lz
    tar -xvf $GMP.tar
    cd $CWD/gmp-6.0.0
    ./configure --enable-cxx --prefix=$SYSROOT --host=$TOOLCHAIN_ARCH CC=$CC LD=$LD RANLIB=$RANLIB CXX=$CXX
    make install
    cd $CWD
}

# Download, patch and compile Relic. The patch is from OpenABE for fixing symbols.
buildRelicForAndroid()
{
    printf "Building Relic\n"
    if [ ! -f $RELIC.tar.gz ]; then
        # check for it in deps/relic
        RELIC_SRC=$ZROOT/deps/relic/$RELIC.tar.gz
        if [ -f $RELIC_SRC ]; then
            tar -xf $RELIC_SRC
        else
            printf "Could not find $RELIC.tar.gz in current directory\n"
            return 1
        fi
    else
        tar -xf $RELIC.tar.gz
    fi

    cd $RELIC/ 
    BP_LABEL=bp
    BP_TMP=$(mktemp -d tmp$BP_LABEL-XXXX)

    EC_LABEL=ec
    EC_TMP=$(mktemp -d tmp$EC_LABEL-XXXX)
    EC_HDR_PREFIX="_$EC_LABEL"

    # Options: BN254 or BN256
    BN_CURVE=254
    EC_CURVE=256

	cd $BP_TMP
	CC="$CC --sysroot=$SYSROOT" RANLIB="$RANLIB" CMAKE_INCLUDE_PATH=$SYSROOT/include CMAKE_LIBRARY_PATH=$SYSROOT/lib
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$SYSROOT -DOPSYS=DROID -DARCH=$RARM \
	-DWITH="BN;DV;FP;FPX;EP;EPX;PP;PC;MD" -DCHECK=off -DVERBS=off -DDEBUG=off \
	-DSHLIB=on -DSTLIB=on -DBENCH=0 -DTESTS=0 -DARITH=gmp -DFP_PRIME="$BN_CURVE" \
	-DFP_QNRES=off -DEP_METHD="PROJC;LWNAF;COMBS;INTER" -DFP_METHD="BASIC;COMBA;COMBA;MONTY;LOWER;SLIDE" \
	-DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DRAND="CALL" \
	-DCOMP="-O3 -funroll-loops -fomit-frame-pointer -I$SYSROOT/include" -DLINK="-L$SYSROOT/lib" -DWORD=$RDWORD ../
	make install

	cd ../$EC_TMP
	CC="$CC --sysroot=$SYSROOT" RANLIB="$RANLIB" CMAKE_INCLUDE_PATH=$SYSROOT/include CMAKE_LIBRARY_PATH=$SYSROOT/lib
	cmake -DCMAKE_INSTALL_PREFIX:PATH=$SYSROOT -DOPSYS=DROID -DARCH=$RARM \
	-DWITH="BN;DV;FP;EP;MD" -DCHECK=off -DVERBS=off -DDEBUG=off \
	-DSHLIB=on -DSTLIB=on -DMULTI=NONE -DBENCH=0 -DTESTS=0 -DARITH=easy -DFP_PRIME="$EC_CURVE" \
	-DFP_QNRES=off -DEP_METHD="PROJC;LWNAF;COMBS;INTER" -DFP_METHD="BASIC;COMBA;COMBA;MONTY;LOWER;SLIDE" \
	-DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DRAND="CALL" \
    -DCOMP="-O3 -funroll-loops -fomit-frame-pointer -I$SYSROOT/include" -DLINK="-L$SYSROOT/lib" -DWORD=$RDWORD \
	-DLABEL="$EC_LABEL" ../
	make install

    # clean up relic includes
	sed -i -e '/^#define VERSION/d' $SYSROOT/include/relic/relic_conf.h
	sed -i -e '/^#define ep2_mul/i \
//#define ep2_mul' $SYSROOT/include/relic/relic_label.h
	sed -i -e '/^#define VERSION/d' $SYSROOT/include/relic$EC_HDR_PREFIX/relic_conf.h

    cd $CWD
}

# Download and compile openssl.         
buildOpenSSLForAndroid()
{
    printf "Building OpenSSL\n"
    if [ ! -f "$OPENSSL.tar.gz" ]; then
        # check for it in deps/openssl
        OPENSSL_SRC=$ZROOT/deps/openssl/$OPENSSL.tar.gz
        if [ -f $OPENSSL_SRC ]; then
            tar -xf $OPENSSL_SRC
        else
            printf "Could not find $OPENSSL.tar.gz in current directory\n"
            return 1
        fi
    else
        tar -xvf $OPENSSL.tar.gz
    fi

    cd $CWD/$OPENSSL
    ./Configure android shared no-async --prefix=$SYSROOT --openssldir=$SYSROOT "-I$ANDROID_NDK_ROOT/platforms/android-14/arch-arm/usr/include/"
    sed -i 's/LDFLAG= -pie/LDFLAG=/g' Makefile
    make CC="$CC" LD=$LD RANLIB=$RANLIB CROSS_SYSROOT=$SYSROOT
    make install_sw CC="$CC" LD=$LD RANLIB=$RANLIB CROSS_SYSROOT=$SYSROOT
    #set +x
    cd $CWD
}

# Download and compile libgtest using the ndk-build tool. 
buildGTestForAndroid()
{
    printf "Building Google Test\n"
    if [ ! -f $GTEST.zip ]; then
        # check for it in deps/gtest
        GTEST_SRC=$ZROOT/deps/gtest/$GTEST.zip
        if [ -f $GTEST_SRC ]; then
            unzip $GTEST_SRC
        else
            printf "Could not find $GTEST.zip in current directory\n"
            return 1
        fi
    else
        unzip $GTEST.zip
    fi

    cd $CWD/$GTEST
    mkdir jni
    echo "
    LOCAL_PATH := \$(call my-dir)
    include \$(CLEAR_VARS)
    LOCAL_CPP_EXTENSION := .cc
    LOCAL_MODULE := libgtest
    LOCAL_C_INCLUDES := include .
    LOCAL_SRC_FILES := ../src/gtest-all.cc
    include \$(BUILD_SHARED_LIBRARY)
    " > ./jni/Android.mk
    echo "
    APP_MODULES := libgtest
    APP_STL := gnustl_shared
    " > ./jni/Application.mk
    $ANDROID_NDK_ROOT/ndk-build
    cp ./libs/armeabi/libgtest.so $SYSROOT/lib/
    cp -r ./include/gtest $SYSROOT/include/
    cd $CWD
}

# Main function to call all of the build functions.
build_main()
{
    buildGMPForAndroid
    buildRelicForAndroid
    buildOpenSSLForAndroid
    buildGTestForAndroid
}

CHECK_ZROOT=`env | grep ZROOT`

if [ -z "$CHECK_ZROOT" ]; then
    printf "Please '. ./env $ANDROID_NDK_ROOT $INSTALLDIR' before running '$0'\n"
    exit 1
fi

build_main
