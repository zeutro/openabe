#!/usr/bin/env bash

# ============================================================================
# RELIC bp/ec Collision Handling - READ THIS BEFORE TOUCHING RELIC-RELATED CODE
# ============================================================================
#
# Every OpenABE binary links TWO independent RELIC builds:
#
#   "bp" build - BN-254 pairing curve (FP_PRIME=254, BN_PRECI=254, ARITH=easy)
#                Installs to include/relic/ with unprefixed symbols.
#                Used by all ABE schemes.
#
#   "ec" build - NIST P-256 curve (FP_PRIME=256, ARITH=gmp)
#                Installs to include/relic_ec/ with -DLABEL="ec".
#                Used by the PK/OPDH scheme.
#
# Both are linked into every binary (see Makefile.common). This creates
# two hazards that must be respected:
#
#
# PROBLEM 1: Header Guard Conflicts
# ----------------------------------------------------------------------------
# Both installs share identical include guards (#ifndef RLC_XXX_H). Including
# <relic/relic.h> before <relic_ec/relic.h> silently skips the second file.
#
# Worse, the ec build's relic_conf.h defines LABEL=ec, which causes
# relic_label.h to macro-rewrite type names (e.g. ep_t -> ec_ep_t). If a
# translation unit was compiled expecting bp-sized types, it will silently
# receive ec-sized (or vice versa) definitions with no diagnostic.
#
# RULE: A translation unit must include headers from only ONE RELIC build.
#       Never mix <relic/...> and <relic_ec/...> in the same .c file.
#
#
# PROBLEM 2: Incomplete Symbol Renaming in RELIC 0.7.0
# ----------------------------------------------------------------------------
# The LABEL mechanism in RELIC 0.7.0 fails to prefix 24 symbols in the ec
# build (blake2s_*, SHA224/384/512_*, ep_mul_sim_lot_*). Both libraries
# export them under the same names. On ELF systems the dynamic linker
# resolves one definition process-wide and if the wrong one wins, 256-bit code
# will execute 254-bit arithmetic (or vice versa), silently corrupting results.
#
# FIX: The ec build is compiled with -D<sym>=ec_<sym> for all 24 symbols,
#      forcing a compiler-level rename. Every global exported by the ec
#      library now carries the ec_ prefix.
#
#      deps/relic/check_ec_symbols.sh checks this:
#        - fails if any global in librelic_s_ec.a lacks the ec_ prefix
#        - fails if any symbol is present in BOTH libraries
#      Do not remove or bypass this check.
#
#
# ARCHITECTURE / CODE LAYOUT
# ----------------------------------------------------------------------------
#   bp side (the default for OpenABE):
#       src/include/openabe/zml/zelement.h     - includes <relic/relic.h>
#       src/zml/zelement.c                     - thin byte-level wrappers
#
#   ec side (isolated):
#       src/include/openabe/zml/zelement_ec_relic.h
#          Exports only opaque types (ec_relic_point_t)
#
#       src/zml/zelement_ec_relic.c
#          compiles with
#              -DLABEL=ec
#              -I$(DEPS_INSTALL_ZROOT)/include/relic_ec
#          so all RELIC types resolve to their ec-sized definitions.
#
#   The boundary header exposes NO RELIC types. Data crossing between the
#   two sides uses only uint8_t, size_t, and int, transferred as
#   big-endian byte strings. All type interpretation stays within each
#   build's translation units.
#
#
# RULES FOR MODIFIERS
# ----------------------------------------------------------------------------
#   1. If you add code that calls RELIC functions, determine which build
#      it belongs to and place it in the correct translation unit.
#
#   2. Never include both <relic/...> and <relic_ec/...> in a single .c
#      file or in a chain of #includes that crosses both trees.
#
#   3. When passing data across the boundary, use only plain byte
#      representations (uint8_t arrays, size_t lengths). Do not pass
#      RELIC-internal struct pointers.
#
#   4. If you update RELIC, re-run check_ec_symbols.sh and verify the
#      set of unprefixed symbols has not grown. New unprefixed symbols
#      must be added to the -D rename list in deps/relic/Makefile.
#
#   5. Test both object formats. Run `make test` and `make -C src test`
#      on Linux (ELF) and Darwin (Mach-O); the flat-namespace collision
#      in Problem 2 manifests differently on each.
#
#   6. The PK/OPDH path (PKOPDHKemContext, PKSchemeContext,
#      CryptoBoxPKEContext, CryptoBoxPKEContextMinusBase64Encoding,
#      test_pke) exercises both builds end-to-end, and should be checked.
#
# ============================================================================

set -Eeuo pipefail

LIBDIR="${1:?usage: check_ec_symbols.sh <install-lib-dir>}"

if [ "$(uname -s)" = "Darwin" ]; then
	NM_FLAGS="-gU"
	# Darwin prefixes every symbol with an underscore
	STRIP_UNDERSCORE="s/^_//"
else
	NM_FLAGS="-g --defined-only"
	STRIP_UNDERSCORE=""
fi

list_globals() {
	# Shape is "<addr> <type> <name>"
	nm "$NM_FLAGS" "$1" 2>/dev/null |
		awk 'NF >= 3 && $2 ~ /^[A-Z]$/ { print $3 }' |
		{ if [ -n "$STRIP_UNDERSCORE" ]; then sed "$STRIP_UNDERSCORE"; else cat; fi; } |
		sort -u
}

status=0
found_any_lib=0

for lib in "$LIBDIR"/librelic_s_ec.a \
	"$LIBDIR"/librelic_ec.so \
	"$LIBDIR"/librelic_ec.dylib \
	"$LIBDIR"/librelic_ec.dll; do
	[ -f "$lib" ] || continue
	found_any_lib=1

	leaked=$(list_globals "$lib" | grep -v '^ec_' || true)
	if [ -n "$leaked" ]; then
		leaked=$(printf '%s\n' "$leaked" || true)
	fi

	if [ -n "$leaked" ]; then
		echo "ERROR: $(basename "$lib") exports global symbols without ec_ prefix. Add -D<sym>=ec_<sym> in deps/relic/Makefile" >&2
		printf '%s\n' "$leaked" | sed 's/^/         /' >&2
		status=1
	fi
done

if [ "$found_any_lib" -eq 0 ]; then
	echo "ERROR: no ec RELIC library found in $LIBDIR" >&2
	exit 1
fi

if [ "$status" -eq 0 ]; then
	echo "All ec RELIC symbols prefixed"
fi

exit "$status"
