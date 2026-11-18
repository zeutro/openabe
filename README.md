# OpenABE

OpenABE is a cryptographic library that incorporates a variety of attribute-based encryption (ABE) algorithms, industry standard cryptographic functions and tools, and an intuitive application programming interface (API). OpenABE is intended to allow developers to seamlessly incorporate ABE technology into applications that would benefit from ABE to protect and control access to sensitive data. OpenABE is designed to be easy to use and does not require developers to be encryption experts.

## Documentation

| Topic | Description |
| --- | --- |
| [ABE overview](docs/abe-overview.md) | What attribute-based encryption is and which algorithms OpenABE implements |
| [Installation](docs/installation.md) | Supported platforms and build instructions for Linux, macOS, Windows and Android |
| [Benchmarking](docs/benchmarking.md) | Performance notes and the `bench_libopenabe` utility |
| [API Guide (PDF)](docs/libopenabe-v1.0.0-api-doc.pdf) | How to install and use the library |
| [CLI Util Document (PDF)](docs/libopenabe-v1.0.0-cli-doc.pdf) | How to use the included command-line tools |
| [Design Document (PDF)](docs/libopenabe-v1.0.0-design-doc.pdf) | Functionalities and algorithms implemented, in detail |

## Quick Start

On Debian/Ubuntu (see [Installation](docs/installation.md) for other platforms):

```bash
sudo -E ./deps/install_pkgs.sh   # once per system
. ./env
make
make test
sudo -E make install
```

To compile the example C++ apps that use the high-level OpenABE crypto box API:

```bash
. ./env
make examples
cd examples/
```

Then run the test app for each supported mode of encryption, plus the keystore example with ABE decryption:

```bash
./test_kp
./test_cp
./test_pk
./test_km
```

## Contributing

If you want to contribute, please refer to [CONTRIBUTING](CONTRIBUTING.md).

[All of our contributors are listed here](CONTRIBUTORS).

## Copyright and License

Copyright (c) 2020 Zeutro, LLC. All rights reserved.

OpenABE is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

OpenABE is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU Affero General Public License](LICENSE) for more details.

You can be released from the requirements of the GNU Affero General Public License and obtain additional features by purchasing a commercial license. Buying such a license is mandatory if you engage in commercial activities involving OpenABE that do not comply with the open source requirements of the GNU Affero General Public License.
