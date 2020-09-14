# OpenABE

OpenABE is a cryptographic library that incorporates a variety of attribute-based encryption (ABE) algorithms, industry standard cryptographic functions and tools, and an intuitive application programming interface (API). OpenABE is intended to allow developers to seamlessly incorporate ABE technology into applications that would benefit from ABE to protect and control access to sensitive data. OpenABE is designed to be easy to use and does not require developers to be encryption experts.

This bundle includes full source code, examples and three main sources of documentation:

1. [OpenABE API Guide Document](https://github.com/zeutro/openabe/blob/master/docs/libopenabe-v1.0.0-api-doc.pdf) - explains how to install and use the library.
2. [OpenABE CLI Util Document](https://github.com/zeutro/openabe/blob/master/docs/libopenabe-v1.0.0-cli-doc.pdf) - shows how to use the included command-line tools, including benchmarking.
3. [OpenABE Design Document](https://github.com/zeutro/openabe/blob/master/docs/libopenabe-v1.0.0-design-doc.pdf) - explains in detail the functionalities and algorithms implemented.

OpenABE is developed by [Zeutro](http://www.zeutro.com). The software is available for use under the [AGPL 3.0 license](https://github.com/zeutro/openabe/blob/master/LICENSE).

## What is Attribute-Based Encryption (ABE)?

Encryption is a method of encoding data that protects the confidentiality of its contents from unauthorized attackers. Traditionally, encryption was viewed as a tool to enable secure communication between a sender and a targeted recipient of information. For example, one might wish to store a message such that it can only be decrypted by the user bob@xyz.org.

Attribute-Based Encryption is a more expansive type of public key encryption that allows for flexible policy-based access controls that are cryptographically (that is, mathematically) enforced. Instead of encrypting data to a single user, it is now possible to encrypt it so that the data can be decrypted by anyone with credentials satisfying an arbitrary attribute-based access control policy.

In OpenABE, any string can potentially serve as an attribute. In addition, attributes can be numeric values and policies can contain ranges over these values. The set of attributes used will depend on the designated application. 

In order to understand the capabilities of ABE, it helps to organize them logically into three variants.

* **Content-Based Access Control** - for granting selective access later (e.g., cloud, email, big data, subpoenas).

	In an ABE system for content-based access control, attributes are associated with a ciphertext and the private key is associated with a policy over these attributes. (In academic literature, this variant is sometimes referred to as "Key-Policy" ABE.)
For example, a company could automatically encrypt all of its emails with the attributes being some (or all) of the 75 fields in Mail headers and then later the company can distribute a key to an analyst that allows for decryption of all emails that meet the policy of `To:engineering@corporation.com` OR (subject contains `cascade project` AND sent between `Dec 21, 2017` and `Jan 10, 2018`.

* **Role-based Access Control** - for policies known at the time of encryption (e.g., classified documents, medical records).

	An ABE system for role-based access control "flips" the semantics of content-based access control. In such a system, attributes are associated with a private key and a policy (or boolean formula) is associated with the ciphertext.  Here the attributes are often be associated with the credentials of a private key holder. (In academic literature this variant is sometimes referred to as "Ciphertext-Policy" ABE.)  For instance, one could restrict a ciphertext only to female employees who have been with the company since 2012 and worked on the "HALE" software project.


* **Multi-authority Role-based Access Control** - for operating across organizational boundaries.

	One issue with role-based access control is that in many applications you may need to write access control policies that span across different administrative boundaries. In standard ABE, there is one authority that hands out private keys. However, in some applications, it is natural for different authorities to manage different attributes. A multi-authority ABE system allows one to associate a ciphertext with a policy written across attributes issued by different authorities. These authorities can operate independently and do not have to coordinate (or even be aware of) each other. 

	For instance, the government might certify the attributes in a person's
driver's license (such as age), while a credit score company could distribute credentials about a user's credit score and an employer could distribute credentials about its employees. With this type of ABE, one can now send out a special offer
readable by anyone over age 50 with a strong credit score and a job at a local employer.


## What cryptographic algorithms are implemented in OpenABE?

OpenABE is a C/C++ software library offering several attribute-based encryption (ABE) schemes together with other core cryptographic functionalities such as authenticated symmetric-key encryption, public key encryption, digital signatures, X.509 certificate handling, key derivation functions, pseudorandom generators and more.

For the full cryptographic technical details inside OpenABE, see the included [OpenABE Design Document](https://github.com/zeutro/openabe/blob/master/docs/libopenabe-v1.0.0-design-doc.pdf).

Application developers should not need to be cryptographic experts to use ABE. To make OpenABE as secure and user-friendly as possible, the following features are provided by default:

1. Collusion-Resistant: Common pitfall in ABE scheme development; Alice and Bob should not be able to combine their private keys to decrypt a ciphertext that neither can decrypt on their own.   Note: any attempt to "engineer" ABE from standard public key encryption usually falls to this attack.
2.  Chosen Ciphertext Attack (CCA) Secure: Prevents serious and practical tampering attacks; most existing schemes in the academic literature only satisfy a weaker security notion (CPA-security).
3.  Unrestricted Attributes: Attributes can be represented by any string (alternative: must enumerate every current and future attribute at system initialization) and can be used an unlimited number of times in a policy.

OpenABE comes with support for efficient and optimized implementations of content-based and role-based ABE schemes. 

For the full cryptographic technical details inside OpenABE, see the included OpenABE Design Document.

## What platforms are supported in OpenABE?

Currently, OpenABE can be installed in the following environments:
- Debian 7-9 and Ubuntu (12.04+)
- CentOS 6/7 and Red Hat Linux 6/7
- Mac OS X (10.8+)
- Windows 7+ (via MINGW)
- Android (NDK r10e)

## Installation

This section describes the installation of the OpenABE source code (`libopenabe-1.0.0-src.tar.gz`) on various platforms. The OpenABE currently supports several operating systems including multiple versions/distros of Linux, Mac OS X and Windows.

### Debian/Ubuntu-based Linux

To compile OpenABE on Ubuntu or Debian Linux-based distro, first run the `deps/install_pkgs.sh` script from the source directory to install the OpenABE system-specific dependencies as follows:
	
	cd libopenabe-1.0.0/
	sudo -E ./deps/install_pkgs.sh

Note that you only have to do this once per system setup. After completion, you can proceed to compile the OpenABE as follows:

	. ./env
	make
	make test

All the unit tests should pass at this point and you can proceed to install the OpenABE in a standard location (`/usr/local`) as follows:

	sudo -E make install

To change the installation path prefix, modify the `INSTALL_PREFIX` variable in `libopenabe-1.0.0/Makefile`.

### CentOS and RedHat Linux

As before, first run the script from the source directory to setup OpenABE dependencies:

	cd libopenabe-1.0.0/
	sudo ./deps/install_pkgs.sh
	scl enable devtoolset-3 bash

Note that you only have to do this once per system setup. After completion, you can proceed to compile the OpenABE as follows:

	. ./env
	make
	make test

All the unit tests should pass at this point and you can proceed to install the OpenABE in a standard location (`/usr/local`) as follows:

	sudo make install

To change the installation path prefix, modify the `INSTALL_PREFIX` variable in `libopenabe-1.0.0/Makefile`.

### Mac OS X

Note that for Mac OS X, you will need [homebrew](http://brew.sh/) installed prior to running the `deps/install_pkgs.sh` script. Then, do the following (you may require `sudo` on the second step):

	cd libopenabe-1.0.0/
	./deps/install_pkgs.sh

Note that you only have to do this once per system setup. After completion, you can proceed to compile the OpenABE as follows:

	. ./env
	make
	make test

All the unit tests should pass at this point and you can proceed to install the OpenABE in a standard location (`/usr/local`) as follows:

	sudo -E make install

To change the installation path prefix, modify the `INSTALL_PREFIX` variable in `libopenabe-1.0.0/Makefile`.

### Windows

To build OpenABE on Windows 7, 8, and 10, you will need to download and install Mingw-w64, 
the GNU toolchain port for building Windows-native binaries. We use the Mingw-w64 port packaged 
with Minimal SYStem 2 (MSYS2). MSYS2 is an emulated POSIX-compliant environment for building 
software with GNU tooling (e.g., GCC), bash, and package management using Arch Linux's Pacman. 
Binaries compiled with these compilers do not require `cygwin.dll` as they are standalone. 

1. Download `msys2-x86_64-latest.exe` and run it. Select `C:\` for the installation directory to avoid `PATH` resolution problems. 

2. Launch the MSYS2 shell and execute the following command: 

        update-core

3. Close the MSYS2 shell and launch the MinGW-w64 Win64 Shell. Note that after starting MSYS2, the prompt will indicate which version you have launched. 

4. Update the pre-installed MSYS2 packages (and install related tooling), close the shell when prompted to, and relaunch the MinGW-w64 Win64 Shell. Execute the following command to start the process:

        pacman -Sy
        pacman -Su base-devel unzip git wget mingw-w64-i686-toolchain \
        mingw-w64-x86_64-toolchain mingw-w64-i686-cmake mingw-w64-x86_64-cmake

5. Install the required third-party libraries by executing the following command: 

        pacman -S gmp-devel mingw-w64-i686-boost mingw-w64-x86_64-boost \
        mingw-w64-x86_64-gtest mingw-w64-i686-gtest

6. In the libopenabe directory, execute the following:
 
        . ./env
        make
        make test
        
7. If all the unit tests pass, then proceed to install the library in a standard location:
			
		 make install

### Android

To build OpenABE for Android, you will need to download and install the Android NDK. The NDK is a toolset that enables cross-compiling C and C++ for ARM and Android-specific libraries and implementations of standard libraries (e.g., GNU STL). We use Android NDK r10e and build on Debian 7.

Download the Android NDK r10e at the following links: 

1. [For Windows-x86_64](http://dl.google.com/android/repository/android-ndk-r10e-windows-x86_64.zip)
2. [For Darwin/Mac OS X-x86_64](https://dl.google.com/android/repository/android-ndk-r10e-darwin-x86_64.zip)
3. [For Linux-x86_64](http://dl.google.com/android/repository/android-ndk-r10e-linux-x86_64.zip)

Unzip the NDK to a directory of your choice. We unzip it to `/opt/android-ndk-r10e/` and will refer to this as `$ANDROID_NDK_ROOT` hereafter.

We build all libraries outside of the OpenABE deps directory. We export the following variables to streamline and contain the build process with a standalone toolchain: 

	export TOOLCHAIN_ARCH=arm-linux-androideabi-4.8 
	export MIN_PLATFORM=android-14
	export INSTALLDIR=$HOME/android

With these variables set, you can now make the standalone toolchain: 

	$ANDROID_NDK_ROOT/build/tools/make-standalone-toolchain.sh \
		--toolchain=$TOOLCHAIN_ARCH --llvm-version=3.6 \
		--platform=$MIN_PLATFORM --install-dir=$INSTALLDIR

Note that 32- and 64-bit architectures are supported for any platform API greater than android-14; However, 64-bit is not supported in the RELIC library for ARM-based processors.

To build for Android, run the following:
	
	./platforms/android.sh $ANDROID_NDK_ROOT $INSTALLDIR
	
In the libopenabe directory, execute the following:

	. ./env $ANDROID_NDK_ROOT $INSTALLDIR
	make src

## Quick Start

To compile example C++ apps that use the high-level OpenABE crypto box API, do the following:

	. ./env
	make examples
	cd examples/

Then, execute the test apps for each mode of encryption supported:

	./test_kp
	./test_cp
	./test_pk
	
You can also execute the example that demonstrates use of the keystore with ABE decryption:
	
	./test_km

## Benchmarking

The OpenABE is built on top of the abstract Zeutro Math library which supplies all of our elliptic-curve operations.  We instantiate our schemes using the state-of-the-art Barreto-Naehrig (BN) curves with the embedding degree `k = 12` (or commonly referred to as `BN-254`). This particular asymmetric curve is known to yield a very efficient pairing implementation and a security level equivalent to `AES-128`. As a result, this boosts the overall performance of ABE scheme implementations over prior efforts. Other benefits of BN curves include the ability to compress the representation of group elements. This directly translates to making ABE ciphertexts more compact which considerably reduces transmission costs.

We include a benchmark utility for all the ABE schemes provided in the OpenABE:

	Math Library: RELIC
	OpenABE benchmark utility, v1.0
	Usage bench_libopenabe: [ scheme => 'CP' or 'KP' ] [ iterations ] \
	               [ attributes ] [ 'fixed' or 'range' ] [ 'cpa' or 'cca']
	-scheme: the type of ABE scheme to benchmark
	-iterations: the number of iterations per test
	-attributes: the number of attributes in the policy or \
                     attribute list for encryption
	-'fixed' or 'range': run with a fixed number of attributes \
	                     or as a range from 1 to num. attributes
	-'cpa' or 'cca': chosen-plaintext secure vs chosen-ciphertext \
	                 secure versions

For example, the command below shows how to benchmark the CCA-secure KP-ABE implementation with 100 attributes for encryption (averaged over 10 iterations). Moreover, the generated decryption key policy will have 100 attributes and each attribute will be involved in the decryption.

	cd src
	bench_libopenabe KP 10 100 fixed cca

## Contributions

### Cryptographic Design

* Brent Waters
* Matthew Green
* Susan Hohenberger Waters
* J. Ayo Akinyele

### Software Design and Development

* J. Ayo Akinyele
* Matthew D. Green
* Alan M. Dunn
* Michael Rushanan

## Copyright and License

Copyright (c) 2020 Zeutro, LLC. All rights reserved.

OpenABE is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

OpenABE is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.

You can be released from the requirements of the GNU Affero General Public License and obtain additional features by purchasing a commercial license. Buying such a license is mandatory if you engage in commercial activities involving OpenABE that do not comply with the open source requirements of the GNU Affero General Public License. 

