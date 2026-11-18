# Installation

This page describes how to build and install OpenABE from source on each supported platform.

- [Supported platforms](#supported-platforms)
- [Debian/Ubuntu-based Linux](#debianubuntu-based-linux)
- [CentOS and Red Hat Linux](#centos-and-red-hat-linux)
- [Mac OS X](#mac-os-x)
- [Windows](#windows)
- [Android](#android)

## Supported platforms

Currently, OpenABE can be installed in the following environments:

- Debian 7-9 and Ubuntu (12.04+)
- CentOS 6/7 and Red Hat Linux 6/7
- Mac OS X (10.8+)
- Windows 7+ (via MINGW)
- Android (NDK r10e)

On every platform except Android, the build follows the same three steps: install the system dependencies once, build and test, then install. To change the installation path prefix (`/usr/local` by default), modify the `INSTALL_PREFIX` variable in the top-level [Makefile](../Makefile).

## Debian/Ubuntu-based Linux

First run the `deps/install_pkgs.sh` script from the source directory to install the OpenABE system-specific dependencies. You only have to do this once per system setup.

```bash
sudo -E ./deps/install_pkgs.sh
```

Then compile OpenABE and run the unit tests:

```bash
. ./env
make
make test
```

All the unit tests should pass at this point. Install OpenABE in the standard location (`/usr/local`):

```bash
sudo -E make install
```

## CentOS and Red Hat Linux

Set up the OpenABE dependencies (once per system setup):

```bash
sudo ./deps/install_pkgs.sh
scl enable devtoolset-3 bash
```

Then compile, test and install:

```bash
. ./env
make
make test
sudo make install
```

## Mac OS X

You need [Homebrew](https://brew.sh/) installed before running the `deps/install_pkgs.sh` script. You may require `sudo` for this step (once per system setup):

```bash
./deps/install_pkgs.sh
```

Then compile, test and install:

```bash
. ./env
make
make test
sudo -E make install
```

## Windows

To build OpenABE on Windows 7, 8, and 10, you will need to download and install Mingw-w64, the GNU toolchain port for building Windows-native binaries. We use the Mingw-w64 port packaged with Minimal SYStem 2 (MSYS2). MSYS2 is an emulated POSIX-compliant environment for building software with GNU tooling (e.g., GCC), bash, and package management using Arch Linux's Pacman. Binaries compiled with these compilers do not require `cygwin.dll` as they are standalone.

1. Download `msys2-x86_64-latest.exe` and run it. Select `C:\` for the installation directory to avoid `PATH` resolution problems.

2. Launch the MSYS2 shell and execute the following command:

   ```bash
   update-core
   ```

3. Close the MSYS2 shell and launch the MinGW-w64 Win64 Shell. Note that after starting MSYS2, the prompt will indicate which version you have launched.

4. Update the pre-installed MSYS2 packages (and install related tooling), close the shell when prompted to, and relaunch the MinGW-w64 Win64 Shell:

   ```bash
   pacman -Sy
   pacman -Su base-devel unzip git wget mingw-w64-i686-toolchain \
     mingw-w64-x86_64-toolchain mingw-w64-i686-cmake mingw-w64-x86_64-cmake
   ```

5. Install the required third-party libraries:

   ```bash
   pacman -S gmp-devel mingw-w64-i686-boost mingw-w64-x86_64-boost \
     mingw-w64-x86_64-gtest mingw-w64-i686-gtest
   ```

6. In the OpenABE directory, execute the following:

   ```bash
   . ./env
   make
   make test
   ```

7. If all the unit tests pass, install the library in a standard location:

   ```bash
   make install
   ```

## Android

To build OpenABE for Android, you will need to download and install the Android NDK. The NDK is a toolset that enables cross-compiling C and C++ for ARM and Android-specific libraries and implementations of standard libraries (e.g., GNU STL). We use Android NDK r10e and build on Debian 7.

Download the Android NDK r10e:

1. [For Windows-x86_64](http://dl.google.com/android/repository/android-ndk-r10e-windows-x86_64.zip)
2. [For Darwin/Mac OS X-x86_64](https://dl.google.com/android/repository/android-ndk-r10e-darwin-x86_64.zip)
3. [For Linux-x86_64](http://dl.google.com/android/repository/android-ndk-r10e-linux-x86_64.zip)

Unzip the NDK to a directory of your choice. We unzip it to `/opt/android-ndk-r10e/` and will refer to this as `$ANDROID_NDK_ROOT` hereafter.

We build all libraries outside of the OpenABE deps directory. Export the following variables to streamline and contain the build process with a standalone toolchain:

```bash
export TOOLCHAIN_ARCH=arm-linux-androideabi-4.8
export MIN_PLATFORM=android-14
export INSTALLDIR=$HOME/android
```

With these variables set, you can now make the standalone toolchain:

```bash
$ANDROID_NDK_ROOT/build/tools/make-standalone-toolchain.sh \
  --toolchain=$TOOLCHAIN_ARCH --llvm-version=3.6 \
  --platform=$MIN_PLATFORM --install-dir=$INSTALLDIR
```

Note that 32- and 64-bit architectures are supported for any platform API greater than android-14; however, 64-bit is not supported in the RELIC library for ARM-based processors.

To build the dependencies for Android, run the following:

```bash
./platforms/android.sh $ANDROID_NDK_ROOT $INSTALLDIR
```

Then, in the OpenABE directory, execute the following:

```bash
. ./env $ANDROID_NDK_ROOT $INSTALLDIR
make src
```
