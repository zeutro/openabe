#!/bin/bash

VERSION=$1
if [[ $VERSION = "" ]]; then
    echo "[!] Missing version as argument"
    exit 0
fi

GTEST_VERSION=googletest-release-${VERSION}.zip
GTEST_LINK=https://github.com/google/googletest/archive/refs/tags/release-${VERSION}.zip

if [[ ! -f ${GTEST_VERSION} ]]; then
    wget -O ${GTEST_VERSION} ${GTEST_LINK}
fi
