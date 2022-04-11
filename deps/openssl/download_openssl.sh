#!/bin/bash

CMD=$1
FORMAT=tar.gz
# commit as of 04/04/2022
COMMIT=3e8f70c30d84861fcd257a6e280dc49e104eb145


LINK=https://github.com/openssl/openssl
VERSION=1.1.1-stable
STABLEBRANCH=OpenSSL_1_1_1-stable
echo "Clone github repo @ ${LINK}"
git clone -b ${STABLEBRANCH} ${LINK} openssl-${VERSION}.git
cd openssl-${VERSION}.git
git reset --hard ${COMMIT}


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
   rm -r openssl-${VERSION}
else
   echo "[!] ${OPENSSL}.${FORMAT} already exists." 
fi

