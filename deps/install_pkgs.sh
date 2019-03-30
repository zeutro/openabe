#!/bin/bash

#set -x
PURPLE='\033[0;95m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

CENTOS_RELEASE=/etc/centos-release
REDHAT_RELEASE=/etc/redhat-release
FEDORA_RELEASE=/etc/fedora-release
LSB_RELEASE=/etc/lsb-release
ORACLE_RELEASE=/etc/oracle-release
SYSTEM_RELEASE=/etc/system-release
DEBIAN_VERSION=/etc/debian_version
function console() {
  echo "[+] $1"
}

function log() {
    printf "${GREEN}[+] $1${NC}\n"
}

function fail() {
  printf "${RED}[!] $1${NC}\n"
  exit 1
}

function platform() {
  local  __out=$1
  if [[ -f "$LSB_RELEASE" ]] && grep -q 'DISTRIB_ID=Ubuntu' $LSB_RELEASE; then
    FAMILY="debian"
    eval $__out="ubuntu"
  elif [[ -f "$DEBIAN_VERSION" ]]; then
    FAMILY="debian"
    eval $__out="debian"
  elif [[ -f "$FEDORA_RELEASE" ]]; then
    FAMILY="fedora"
    eval $__out="fedora"
  elif [[ -f "$CENTOS_RELEASE" ]]; then
    FAMILY="centos"
    eval $__out="centos"
  elif [[ -f "$REDHAT_RELEASE" ]]; then
    FAMILY="redhat"
    eval $__out="redhat"
  else
    eval $__out=`uname -s | tr '[:upper:]' '[:lower:]'`
  fi
}

function distro() {
  local __out=$2
  if [[ $1 = "ubuntu" ]]; then
    eval $__out=`awk -F= '/DISTRIB_CODENAME/ { print $2 }' $LSB_RELEASE`
  elif [[ $1 = "darwin" ]]; then
    eval $__out=`sw_vers -productVersion | awk -F '.' '{print $1 "." $2}'`
  elif [[ $1 = "debian" ]]; then
    eval $__out="`lsb_release -cs`"
  elif [[ $1 = "fedora" ]]; then
    eval $__out="`cat $FEDORA_RELEASE | tr -dc 0-9`"
  elif [[ $1 = "centos" ]]; then
    eval $__out="`cat $CENTOS_RELEASE | tr -dc .0-9`"
  elif [[ $1 = "redhat" ]]; then
    eval $__out="`cat $REDHAT_RELEASE | tr -dc .0-9`"
  else
    eval $__out="unknown_version"
  fi
}

function install_package() {
  if [[ $FAMILY = "debian" ]]; then
    if [[ -n "$(dpkg --get-selections | grep $1)" ]]; then
      console "$1 is already installed. skipping."
    else
      console "installing $1"
      sudo DEBIAN_FRONTEND=noninteractive apt-get install $1 -y
    fi
  elif [[ $OS = "darwin" ]]; then
    if [[ -n "$(brew list | grep $1)" ]]; then
      console "$1 is already installed. skipping."
    else
      console "installing $1"
      #unset LIBNAME
      #unset HOMEBREW_BUILD_FROM_SOURCE
      export HOMEBREW_NO_EMOJI=1
      if [[ $1 = "gnu-sed" ]]; then
        HOMEBREW_ARGS="--with-default-names"
      else
        HOMEBREW_ARGS=""
      fi
      brew install $HOMEBREW_ARGS $1 || brew upgrade -v $HOMEBREW_ARGS $@
      if [[ $1 = "bison" || $1 = "lua" || $1 = "coreutils" ]]; then
         brew link $1 --force
      fi
    fi
  elif [[ $OS = "redhat" || $OS = "centos" ]]; then
    # add logic to differentiate between rhel 6 vs rhel 7, etc
    console "installing $1"
    sudo yum -y install $1
  elif [[ $OS = "fedora" ]]; then
    if [[ $OS_VERSION > 21 ]]; then
      console "$OS_VERSION > 21"
    else
      #if [[ $(yum list installed | grep $1) ]]; then
      #  console "$1 is already installed. skipping."
      #else
      console "installing $1"
      sudo yum -y install $1
      #fi
    fi
  fi
}

# packages needed for Mac OS X
function main_darwin() {
  type brew >/dev/null 2>&1 || {
    fail "Could not find homebrew. Please install it from http://brew.sh/";
  }

  type pip >/dev/null 2>&1 || {
    fail "Could not find pip. please install it using 'sudo easy_install pip'";
  }

  brew update

  install_package wget
  install_package cmake
  install_package gnu-sed
  install_package coreutils
  install_package autoconf
  install_package automake
  install_package libtool
  install_package pkg-config
  install_package python
  install_package gmp
  install_package doxygen
  install_package bison
  install_package node

  sudo pip install virtualenv
}

function upgrade_cmake() {

  # check if cmake has been installed already
  CMAKE_CHECK=`cmake --version`
  STATUS=$?

  if [[ $STATUS -eq 0 ]]; then
     CMAKE_VERS=`cmake --version | grep version | cut -b 15-17 | tr -d [.]`
     if [[ $CMAKE_VERS -gt 30 ]]; then
        echo "[+] cmake version greater than or equal to 3.1. skipping upgrade."
        return 0
     else # in case, already installed as cmake3 instead
        CMAKE3_VERS=`cmake3 --version | grep version | cut -b 16-18 | tr -d [.]`
        if [[ $CMAKE3_VERS -gt 30 ]]; then
            echo "[+] cmake3 version greater than or equal to 3.1. skipping upgrade."
            return 0	
	fi
     fi
  fi

  # install cmake from source
  echo "[+] Install cmake v3.2"
  CMAKE32=cmake-3.2.2
  if [[ ! -f ${CMAKE32}/.built ]]; then
     wget https://www.cmake.org/files/v3.2/${CMAKE32}.tar.gz
     tar xf ${CMAKE32}.tar.gz
     cd ${CMAKE32}
     ./configure
     make install
     touch .built
     cd ..
  else
     cd ${CMAKE32}
     make install 
     cd ..
  fi
}

function upgrade_bison() {
  BISON30=bison-3.0
  BISON_URL=https://ftp.gnu.org/gnu/bison/${BISON30}.tar.gz
 
  # check the existing version first
  BISON_VERSION=`bison --version | grep Bison | cut -b 19-21 | tr -d [.]`
  if [[ ${BISON_VERSION} -ge 30 ]]; then
     echo "[+] bison version is 3.0 or greater. skipping upgrade"
     return 0
  fi

  if [[ ! -f ${BISON30}/.built ]]; then
     wget ${BISON_URL}
     tar xf ${BISON30}.tar.gz
     cd ${BISON30}
     ./configure
     make install
     touch .built
     cd ..
  fi
}

# packages needed for Linux/Ubuntu distro
function main_ubuntu() {
  sudo apt-get update
  install_package python-pip

  type pip >/dev/null 2>&1 || {
    fail "Could not find pip. please install it using 'sudo easy_install pip'";
  }

  install_package wget
  install_package autoconf
  install_package m4
  install_package libtool
  install_package g++
  install_package cmake
  install_package libgmp-dev
  install_package libssl-dev
  install_package bison
  install_package flex
  install_package unzip
  install_package libglib2.0-dev
  install_package doxygen
  install_package python3-setuptools
  install_package python3-dev
  install_package python3-pip
  install_package nodejs
  install_package npm
  upgrade_cmake
  upgrade_bison
  
  sudo ldconfig
}

function main_debian() {
  sudo apt-get update

  install_package wget
  install_package autoconf
  install_package m4
  install_package libtool
  install_package g++
  install_package cmake
  install_package libgmp-dev
  install_package libssl-dev
  install_package bison
  install_package flex
  install_package unzip
  install_package libglib2.0-dev
  install_package doxygen
  install_package python3-setuptools
  install_package python3-dev
  install_package python3-pip
  install_package nodejs
  install_package npm
  upgrade_cmake
  upgrade_bison

  sudo ldconfig
}

function main_redhat() {
    
  yum -y update
  yum install -y centos-release-scl
  yum install -y devtoolset-3-toolchain
  yum install -y epel-release
  
  install_package wget
  install_package autoconf
  install_package m4
  install_package cmake3
  ln -s `which cmake3` /usr/bin/cmake
  install_package libtool
  install_package gcc
  install_package gcc-c++
  install_package gmp-devel
  install_package bison
  install_package flex
  install_package unzip
  install_package glib-devel
  install_package doxygen
  install_package python36
  install_package python-pip
  install_package python-devel
  install_package python-setuptools  
  install_package python36-setuptools
  install_package python36-devel
  install_package python36-pip  
  upgrade_cmake
  upgrade_bison
  echo "/usr/local/lib" > /etc/ld.so.conf.d/libztk.conf
  
  sudo ldconfig
}

function main_fedora() {
    
  yum -y update
  
  install_package wget
  install_package autoconf
  install_package m4
  install_package libtool
  install_package gcc
  install_package gcc-c++
  install_package gmp-devel
  install_package bison
  install_package flex
  install_package unzip
  install_package glib-devel
  install_package doxygen
  install_package python3
  install_package python-pip
  install_package python-devel
  install_package python-setuptools  
  install_package python3-setuptools
  install_package python3-devel
  install_package python3-pip  
  upgrade_cmake
  upgrade_bison
  
  sudo ldconfig
}


function main() {
  platform OS
  distro $OS OS_VERSION

  if [[ $1 = "get_platform" ]]; then
    printf "OS:\t$OS\n"
    printf "VER:\t$OS_VERSION\n"
    return 0
  fi

  if [[ $OS = "ubuntu" ]]; then
    log "Detected Ubuntu ($OS_VERSION)"
    main_ubuntu
  elif [[ $OS = "darwin" ]]; then
    log "Detected Mac OS X ($OS_VERSION)"
    main_darwin
  elif [[ $OS = "debian" ]]; then
    log "Detected Debian ($OS_VERSION)"
    main_debian
  elif [[ $OS = "centos" ]]; then
    log "Detected CentOS ($OS_VERSION)"
    main_redhat $OS_VERSION
    scl enable devtoolset-3 bash
  elif [[ $OS = "redhat" ]]; then
    log "Detected Redhat ($OS_VERSION)"
    main_redhat $OS_VERSION
  elif [[ $OS = "fedora" ]]; then
    log "Detected Fedora ($OS_VERSION)"
    main_fedora $OS_VERSION
  else
    fail "Could not detect the OS."
  fi
}

main $1

#set +x
