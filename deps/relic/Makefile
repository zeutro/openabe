# this file is based on the following file of the OpenABE library:
# https://github.com/zeutro/openabe/blob/master/deps/relic/Makefile
# with minor modifications made by IBM to allow compilation with ARM architecture
# extracted from: https://github.com/IBM/openabe/blob/master/src/Makefile
# and minor modifications following the issue solved in: https://github.com/relic-toolkit/relic/issues/211

.PHONY: all clean

include ../../Makefile.common

VERSION = 0.7.0
BP_LABEL = bp
BP_TMP = tmp$(BP_LABEL)
BP_HDR_PREFIX = _$(BP_LABEL)

EC_LABEL = ec
EC_TMP = tmp$(EC_LABEL)
EC_HDR_PREFIX = _$(EC_LABEL)

# Options: BN254 or BN382 (ARITH=x64-asm-382)
BN_CURVE = 254
EC_CURVE = 256

# RELIC's own include/relic_label.h renames *most* of the library when LABEL is set, which is how
# the ec build gets its ec_ prefix. It does not cover *everything*, however. The following symbols
# below stay unprefixed (as of RELIC 0.7.0), so without these -D flags librelic_ec exports them
# under the same names as librelic. Depending on the executable format (Mach-O vs. ELF), this may
# be invisible or turn into a face condition, and is silent unless you inspect the function
# behavior
EC_RENAME = \
	-Dbn_div_exc=$(EC_LABEL)_bn_div_exc \
	-Dbn_div_rem_rup=$(EC_LABEL)_bn_div_rem_rup \
	-Dbn_dive_low=$(EC_LABEL)_bn_dive_low \
	-Dbn_map_prime=$(EC_LABEL)_bn_map_prime \
	-Dbn_mul_add=$(EC_LABEL)_bn_mul_add \
	-Dbn_mul_sub=$(EC_LABEL)_bn_mul_sub \
	-Dbn_mxp_lower=$(EC_LABEL)_bn_mxp_lower \
	-Dbn_mxpn_itch_low=$(EC_LABEL)_bn_mxpn_itch_low \
	-Dbn_mxpn_low=$(EC_LABEL)_bn_mxpn_low \
	-Dbn_srt_mod=$(EC_LABEL)_bn_srt_mod \
	-Dmd_xof_bits=$(EC_LABEL)_md_xof_bits \
	-Dmd_xof_bytes=$(EC_LABEL)_md_xof_bytes \
	-Dmd_xof_double=$(EC_LABEL)_md_xof_double \
	-Dmd_xof_init=$(EC_LABEL)_md_xof_init \
	-Dmd_xof_int=$(EC_LABEL)_md_xof_int \
	-Dblake2s=$(EC_LABEL)_blake2s \
	-Dblake2s_final=$(EC_LABEL)_blake2s_final \
	-Dblake2s_init=$(EC_LABEL)_blake2s_init \
	-Dblake2s_init_key=$(EC_LABEL)_blake2s_init_key \
	-Dblake2s_init_param=$(EC_LABEL)_blake2s_init_param \
	-Dblake2s_update=$(EC_LABEL)_blake2s_update \
	-Dep_mul_sim_lot_endom=$(EC_LABEL)_ep_mul_sim_lot_endom \
	-Dep_mul_sim_lot_plain=$(EC_LABEL)_ep_mul_sim_lot_plain \
	-DSHA224FinalBits=$(EC_LABEL)_SHA224FinalBits \
	-DSHA224Input=$(EC_LABEL)_SHA224Input \
	-DSHA224Reset=$(EC_LABEL)_SHA224Reset \
	-DSHA224Result=$(EC_LABEL)_SHA224Result \
	-DSHA256FinalBits=$(EC_LABEL)_SHA256FinalBits \
	-DSHA256Input=$(EC_LABEL)_SHA256Input \
	-DSHA256Reset=$(EC_LABEL)_SHA256Reset \
	-DSHA256Result=$(EC_LABEL)_SHA256Result \
	-DSHA384FinalBits=$(EC_LABEL)_SHA384FinalBits \
	-DSHA384Input=$(EC_LABEL)_SHA384Input \
	-DSHA384Reset=$(EC_LABEL)_SHA384Reset \
	-DSHA384Result=$(EC_LABEL)_SHA384Result \
	-DSHA512FinalBits=$(EC_LABEL)_SHA512FinalBits \
	-DSHA512Input=$(EC_LABEL)_SHA512Input \
	-DSHA512Reset=$(EC_LABEL)_SHA512Reset \
	-DSHA512Result=$(EC_LABEL)_SHA512Result

# RELIC 0.7.0's CMakeLists.txt takes its compiler flags from the CFLAGS environment variable, not
# from COMP. Setting CFLAGS replaces RELIC's own default flag string outright, so that string is repeated here with EC_RENAME appended.
EC_CFLAGS = -pipe -std=c99 -O2 -funroll-loops -fomit-frame-pointer $(EC_RENAME)

all: relic-$(VERSION)/.built

# We remove the VERSION define from (the installed) relic_conf.h
# because this conflicts with other libraries.  Actually, they
# shouldn't really include relic_conf.h in anywhere other than C
# files.
#
# We also undefine MIN and MAX before they are redefined.
#
#-DLABEL="$(BP_LABEL)"
relic-$(VERSION)/.built: | relic-$(VERSION)
	mkdir -p $(BP_TMP) $(EC_TMP)
	cd $(BP_TMP) && \
	COMP="-O2 -funroll-loops -fomit-frame-pointer -Wno-incompatible-pointer-types -Wno-unused-function -Wno-implicit-function-declaration -Wno-incompatible-pointer-types-discards-qualifiers -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security" cmake $(COMPILER_VARS) $(CMAKE_VARS) -DCMAKE_INSTALL_PREFIX:PATH="$(DEPS_INSTALL_ZROOT)" -DOPSYS=$(RELIC_OS) -DARCH="X64" -DWSIZE=64 -DWITH="BN;DV;FP;FPX;EP;EPX;PP;PC;MD" -DCHECK=off -DVERBS=off -DDEBUG=off -DMULTI=PTHREAD -DBENCH=0 -DTESTS=0 -DARITH=easy -DFP_PRIME=$(BN_CURVE) -DBN_PRECI=$(BN_CURVE) -DFP_QNRES=on -DEP_METHD="PROJC;LWNAF;COMBS;INTER;SSWUM" -DFP_METHD="BASIC;COMBA;COMBA;MONTY;JMPDS;JMPDS;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DRAND="CALL" ../relic-$(VERSION); \
	$(MINGW_MAKE) && \
	$(MINGW_MAKE) install && \
	cd ../$(EC_TMP) && \
	CFLAGS="$(EC_CFLAGS)" \
	COMP="-O2 -funroll-loops -fomit-frame-pointer -Wno-unused-function -Wno-implicit-function-declaration -Wno-incompatible-pointer-types-discards-qualifiers -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security" cmake $(COMPILER_VARS) $(CMAKE_VARS) -DCMAKE_INSTALL_PREFIX:PATH="$(DEPS_INSTALL_ZROOT)" -DOPSYS=$(RELIC_OS) -DARCH="X64" -DWSIZE=64 -DWITH="BN;DV;FP;EP;MD" -DCHECK=off -DVERBS=off -DDEBUG=off -DMULTI=PTHREAD -DBENCH=0 -DTESTS=0 -DARITH=gmp -DFP_PRIME=$(EC_CURVE) -DFP_QNRES=off -DEP_METHD="PROJC;LWNAF;COMBS;INTER;SSWUM" -DFP_METHD="BASIC;COMBA;COMBA;MONTY;JMPDS;JMPDS;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DRAND="CALL" -DLABEL="$(EC_LABEL)" ../relic-$(VERSION); \
	$(MINGW_MAKE) && \
	$(MINGW_MAKE) install && \
	sed -i -e '/^#define VERSION/d' "$(DEPS_INSTALL_ZROOT)"/include/relic/relic_conf.h && \
	sed -i -e '/^#define ep2_mul/i \
	//#define ep2_mul' "$(DEPS_INSTALL_ZROOT)/include/relic/relic_label.h" && \
	sed -i -e '/^#define VERSION/d' "$(DEPS_INSTALL_ZROOT)/include/relic$(EC_HDR_PREFIX)/relic_conf.h" && \
	cd .. && \
	mkdir -p "$(DEPS_INSTALL_ZROOT)/bin" && \
	{ test ! -f "$(BP_TMP)/lib/librelic.dll" || cp "$(BP_TMP)/lib/librelic.dll" "$(DEPS_INSTALL_ZROOT)/bin/"; } && \
	{ test ! -f "$(EC_TMP)/lib/librelic_ec.dll" || cp "$(EC_TMP)/lib/librelic_ec.dll" "$(DEPS_INSTALL_ZROOT)/bin/"; } && \
	./check_ec_symbols.sh "$(DEPS_INSTALL_ZROOT)/lib" && \
	./run_install_clean.sh && \
	touch "relic-$(VERSION)/.built"

relic-$(VERSION).tar.gz:
	./download_relic.sh relic-$(VERSION)

relic-$(VERSION): relic-$(VERSION).tar.gz
	tar xf $^
	# relic_core.h declares rand_call's length argument as int, but every caller
	# passes size_t, even within RELIC. Until fixed by upstream, we patch this.
	sed -i.bak 's/void (\*rand_call)(uint8_t \*, int, void \*);/void (*rand_call)(uint8_t *, size_t, void *);/' \
	  relic-$(VERSION)/include/relic_core.h
	rm -f relic-$(VERSION)/include/relic_core.h.bak

clean:
	rm -rf relic-$(VERSION) tmp*

distclean:
	rm -rf relic-$(VERSION)* tmp*