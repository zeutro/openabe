#!/bin/bash

VERSION=0.7.0
FORMAT=tar.gz
LINK=https://github.com/relic-toolkit/relic
RELIC=${1:-relic-toolkit-${VERSION}}

echo "Clone github repo @ ${LINK}"
git clone ${LINK} ${RELIC}.git
cd ${RELIC}.git

if [[ ! -f ${RELIC}.${FORMAT} ]]; then
	echo "Create archive of source (without git files)"
	git archive --output ../${RELIC}.test.${FORMAT} HEAD

	echo "Create final tarball: ${RELIC}.${FORMAT}"
	cd ..
	mkdir ${RELIC}
	cd ${RELIC}
	tar -xf ../${RELIC}.test.${FORMAT}

	cd ..
	tar -czf ${RELIC}.${FORMAT} ${RELIC}
	rm ${RELIC}.test.${FORMAT}
	rm -rf ${RELIC}
else
	echo "[!] ${RELIC}.tar.gz already exists."
fi
