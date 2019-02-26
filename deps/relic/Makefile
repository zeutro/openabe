.PHONY: all clean

include ../../Makefile.common

VERSION=toolkit-0.5.0
BP_LABEL=bp
BP_TMP=$(shell mktemp -d tmp$(BP_LABEL)-XXXX)
BP_HDR_PREFIX=_$(BP_LABEL)

EC_LABEL=ec
EC_TMP=$(shell mktemp -d tmp$(EC_LABEL)-XXXX)
EC_HDR_PREFIX=_$(EC_LABEL)

# Options: BN254 or BN382 (ARITH=x64-asm-382)
BN_CURVE=254
EC_CURVE=256

all: package relic-$(VERSION)/.built

# We remove the VERSION define from (the installed) relic_conf.h
# because this conflicts with other libraries.  Actually, they
# shouldn't really include relic_conf.h in anywhere other than C
# files.
#
# We also undefine MIN and MAX before they are redefined.
#
#-DLABEL="$(BP_LABEL)"
relic-$(VERSION)/.built: relic-${VERSION}
	cd $(BP_TMP); \
	$(CMAKE_VARS) COMP="-O2 -funroll-loops -fomit-frame-pointer -Wno-incompatible-pointer-types -Wno-unused-function -Wno-implicit-function-declaration -Wno-incompatible-pointer-types-discards-qualifiers" cmake $(COMPILER_VARS) -DCMAKE_INSTALL_PREFIX:PATH=$(DEPS_INSTALL_ZROOT) -DOPSYS=$(RELIC_OS) -DARCH="X64" \
	-DWITH="BN;DV;FP;FPX;EP;EPX;PP;PC;MD" -DCHECK=off -DVERBS=off -DDEBUG=off -DMULTI=PTHREAD -DBENCH=0 -DTESTS=10 -DARITH=x64-asm-$(BN_CURVE) -DFP_PRIME=$(BN_CURVE) -DBN_PRECI=$(BN_CURVE) \
	-DFP_QNRES=on -DEP_METHD="PROJC;LWNAF;COMBS;INTER" -DFP_METHD="BASIC;COMBA;COMBA;MONTY;LOWER;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" \
	-DSEED="ZERO" -DRAND="CALL" ../$<; \
	make && \
	make install && \
	cd ../$(EC_TMP); \
	$(CMAKE_VARS) COMP="-O2 -funroll-loops -fomit-frame-pointer -Wno-unused-function -Wno-implicit-function-declaration -Wno-incompatible-pointer-types-discards-qualifiers" cmake $(COMPILER_VARS) -DCMAKE_INSTALL_PREFIX:PATH=$(DEPS_INSTALL_ZROOT) -DOPSYS=$(RELIC_OS) -DARCH="X64" \
	-DWITH="BN;DV;FP;EP;MD" -DCHECK=off -DVERBS=off -DDEBUG=off -DMULTI=PTHREAD -DBENCH=0 -DTESTS=0 -DARITH=gmp -DFP_PRIME=$(EC_CURVE) \
	-DFP_QNRES=off -DEP_METHD="PROJC;LWNAF;COMBS;INTER" -DFP_METHD="BASIC;COMBA;COMBA;MONTY;LOWER;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" \
	-DSEED="ZERO" -DRAND="CALL" -DLABEL="$(EC_LABEL)" ../$<; \
	make && \
	make install && \
	sed -i -e '/^#define VERSION/d' $(DEPS_INSTALL_ZROOT)/include/relic/relic_conf.h && \
	sed -i -e '/^#define ep2_mul/i \
//#define ep2_mul' $(DEPS_INSTALL_ZROOT)/include/relic/relic_label.h && \
	sed -i -e '/^#define VERSION/d' $(DEPS_INSTALL_ZROOT)/include/relic$(EC_HDR_PREFIX)/relic_conf.h && \
	../run_install_clean.sh && \
	touch ../$@

relic-$(VERSION): relic-$(VERSION).tar.gz
	tar xf $^

package:
	./download_relic.sh relic-$(VERSION)

clean:
	rm -rf relic-$(VERSION) tmp*

distclean:
	rm -rf relic-$(VERSION)* tmp* 
