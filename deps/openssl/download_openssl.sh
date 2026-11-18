#!/bin/bash

CMD=$1
FORMAT=tar.gz
VERSION=4.0.1
TAG=openssl-${VERSION}
LINK=https://github.com/openssl/openssl
echo "Clone github repo @ ${LINK} (tag ${TAG})"
git clone --branch ${TAG} --depth 1 ${LINK} openssl-${VERSION}.git
cd openssl-${VERSION}.git

OPENSSL=openssl-${VERSION}
if [[ ! -f ./${OPENSSL}.${FORMAT} ]]; then
	echo "Create archive of source (without git files)"
	git archive --output ../openssl-${VERSION}.test.${FORMAT} HEAD

	echo "Create final tarball: openssl-${VERSION}.${FORMAT}"
	cd ..
	mkdir -p openssl-${VERSION}
	cd openssl-${VERSION}
	tar -xf ../openssl-${VERSION}.test.${FORMAT}

	cd ..
	tar -czf openssl-${VERSION}.${FORMAT} openssl-${VERSION}
	rm openssl-${VERSION}.test.${FORMAT}
	rm -rf openssl-${VERSION}
else
	echo "[!] ${OPENSSL}.${FORMAT} already exists."
fi
