///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// This file is part of Zeutro's OpenABE.
///
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
///
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
///
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
///
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \file   zelement.h
///
/// \brief  Base class definition for ZTK groups (EC/pairings)
///
/// deps/relic/Makefile builds RELIC twice into one prefix: "bp" (BN-254 pairing, no LABEL) which
/// all ABE scheme use, and "ec" (NIST-256, LABEL="ec") that non-ABE PK/OPDH use. This is compiled
/// against the latter, exclusively, so everything else is OpenABE-used "bp"
///
/// Scalars/coordinates are big-endian bytes instead of RELIC objects because those differ between
/// between the two builds or only match coincidentally

#ifndef __ZELEMENT_EC_RELIC_H__
#define __ZELEMENT_EC_RELIC_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Upper bound on the byte width of anything that crosses this boundary: a
/// group order or a field element. The widest curve offered here is NIST
/// P-521, at 66 bytes. Callers size their stack buffers with this and check
/// the value the ec side actually reports against it.
#define EC_RELIC_MAX_BYTES 128

/// Opaque handle for a point on the ec build's curve. The struct is defined
/// in zelement_ec_relic.c, the only place that knows the ec build's ep_t.
typedef struct ec_relic_point_st* ec_relic_point_t;

/// Initialize and tear down the ec build's own RELIC context. Separate from
/// the bp build's core_init()/core_clean(), which the caller drives itself.
int ec_relic_core_init(void);
int ec_relic_core_clean(void);

/// Select the active curve. Takes the NIST curve size in bits: 256, 384 or
/// 521. Returns 0 on success, -1 for an unknown size.
int ec_relic_param_set(int curve_bits);

/// Write the group order of the active curve into out, big-endian, and
/// return the number of bytes written. Returns 0 if outlen is too small.
size_t ec_relic_order_bin(uint8_t* out, size_t outlen);

/// Size in bytes of one field element, which is the width
/// ec_relic_point_coord_bin writes per coordinate.
size_t ec_relic_field_bytes(void);

/// Allocate a point. Returns NULL on allocation failure. Every point from
/// this function must be released with ec_relic_point_free.
ec_relic_point_t ec_relic_point_new(void);
void ec_relic_point_free(ec_relic_point_t p);

void ec_relic_point_copy(ec_relic_point_t to, const ec_relic_point_t from);
void ec_relic_point_set_inf(ec_relic_point_t p);
int ec_relic_point_is_inf(const ec_relic_point_t p);
int ec_relic_point_is_on_curve(const ec_relic_point_t p);
int ec_relic_point_cmp(const ec_relic_point_t a, const ec_relic_point_t b);
void ec_relic_point_add(ec_relic_point_t r, const ec_relic_point_t a, const ec_relic_point_t b);

/// r = a * k, where k is a big-endian scalar of klen bytes.
void ec_relic_point_mul(ec_relic_point_t r, const ec_relic_point_t a, const uint8_t* k,
                        size_t klen);

void ec_relic_generator(ec_relic_point_t g);

/// Serialization. pack is 1 for the compressed encoding, 0 for uncompressed.
size_t ec_relic_point_size_bin(const ec_relic_point_t p, int pack);
void ec_relic_point_write_bin(uint8_t* out, size_t len, const ec_relic_point_t p, int pack);
void ec_relic_point_read_bin(ec_relic_point_t p, const uint8_t* in, size_t len);

/// Write p's affine x and y coordinates, each big-endian and each exactly len
/// bytes wide. len must equal ec_relic_field_bytes(). Returns 0 on success,
/// -1 for any other len.
int ec_relic_point_coord_bin(uint8_t* xout, uint8_t* yout, size_t len, const ec_relic_point_t p);

#ifdef __cplusplus
}
#endif

#endif /* ifdef __ZELEMENT_EC_RELIC_H__ */
