#!/bin/bash

VERSION=0.4.1h
FORMAT=tar.gz
LINK=https://github.com/relic-toolkit/relic
RELIC=${1:-relic-toolkit-${VERSION}}
# commit as of 4/2/2018
# comment 'Merge pull request #73'
COMMIT=6609c924395ab6a48955c74558dda38b638b5cba

echo "Clone github repo @ ${LINK}"
git clone ${LINK} ${RELIC}.git
cd ${RELIC}.git
git reset --hard ${COMMIT}

if [[ ! -f ${RELIC}.${FORMAT} ]]; then
   echo "Create archive of source (without git files)"
   git archive --output ../${RELIC}.test.${FORMAT} HEAD 

   echo "Create final tarball: ${RELIC}.${FORMAT}"
   cd ..
   mkdir ${RELIC}
   cd ${RELIC}
   tar -xf ../${RELIC}.test.${FORMAT}

   echo "Fix symbols..."
   grep -rl "MIN" ./ | xargs sed --in-place 's/MIN/RLC_MIN/g'
   grep -rl "MAX" ./ | xargs sed --in-place 's/MAX/RLC_MAX/g'
   grep -rl "ALIGN" ./ | xargs sed --in-place 's/ALIGN/RLC_ALIGN/g'
   grep -rl "rsa_t" ./ | xargs sed --in-place 's/rsa_t/rlc_rsa_t/g'
   grep -rl "rsa_st" ./ | xargs sed --in-place 's/rsa_st/rlc_rsa_st/g'
   sed --in-place -e '/^#define ep2_mul /d' include/relic_label.h

   cd ..
   tar -czf ${RELIC}.${FORMAT} ${RELIC}
   rm ${RELIC}.test.${FORMAT}
   rm -r ${RELIC}
else
   echo "[!] ${RELIC}.tar.gz already exists." 
fi
