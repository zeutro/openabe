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
/// \file   zelement_ec_relic.c
///
/// \brief  The one translation unit compiled against RELIC's "ec" build.
///
/// src/Makefile compiles this file with -DLABEL=ec and with the ec build's
/// own include directory, so <relic.h> below resolves to
/// deps/root/include/relic_ec/relic.h and RELIC's include/relic_label.h
/// renames the whole library to its ec_ form for this file. Plain ep_t, bn_t
/// and fp_t therefore mean the ec build's real types at their real sizes.
///
/// Do not include zelement.h here, or any header that reaches it: that pulls
/// in the bp build's headers, and the two cannot be parsed in one translation
/// unit.

#include <stdlib.h>
#include <string.h>

#include <relic.h>

#include <openabe/zml/zelement_ec_relic.h>

struct ec_relic_point_st {
  ep_t p;
};

int ec_relic_core_init(void) {
  return core_init();
}

int ec_relic_core_clean(void) {
  return core_clean();
}

int ec_relic_param_set(int curve_bits) {
  switch (curve_bits) {
  case 256:
    ep_param_set(NIST_P256);
    break;
  case 384:
    ep_param_set(NIST_P384);
    break;
  case 521:
    ep_param_set(NIST_P521);
    break;
  default:
    return -1;
  }
  return 0;
}

size_t ec_relic_order_bin(uint8_t* out, size_t outlen) {
  bn_t order;
  size_t len = 0;

  bn_null(order);
  bn_new(order);
  ep_curve_get_ord(order);
  len = bn_size_bin(order);
  if (len > outlen) {
    len = 0;
  } else {
    bn_write_bin(out, len, order);
  }
  bn_free(order);
  return len;
}

size_t ec_relic_field_bytes(void) {
  return RLC_FP_BYTES;
}

ec_relic_point_t ec_relic_point_new(void) {
  ec_relic_point_t h = calloc(1, sizeof(struct ec_relic_point_st));
  if (h == NULL) {
    return NULL;
  }
  ep_null(h->p);
  ep_new(h->p);
  return h;
}

void ec_relic_point_free(ec_relic_point_t p) {
  if (p == NULL) {
    return;
  }
  ep_free(p->p);
  free(p);
}

void ec_relic_point_copy(ec_relic_point_t to, const ec_relic_point_t from) {
  ep_copy(to->p, from->p);
}

void ec_relic_point_set_inf(ec_relic_point_t p) {
  ep_set_infty(p->p);
}

int ec_relic_point_is_inf(const ec_relic_point_t p) {
  /* 1 if the point is at infinity, 0 otherwise. */
  return ep_is_infty(p->p);
}

int ec_relic_point_is_on_curve(const ec_relic_point_t p) {
  return ep_on_curve(p->p) ? 1 : 0;
}

int ec_relic_point_cmp(const ec_relic_point_t a, const ec_relic_point_t b) {
  return ep_cmp(a->p, b->p);
}

void ec_relic_point_add(ec_relic_point_t r, const ec_relic_point_t a, const ec_relic_point_t b) {
  ep_add(r->p, a->p, b->p);
  ep_norm(r->p, r->p);
}

void ec_relic_point_mul(ec_relic_point_t r, const ec_relic_point_t a, const uint8_t* k,
                        size_t klen) {
  bn_t scalar;

  bn_null(scalar);
  bn_new(scalar);
  bn_read_bin(scalar, k, klen);
  ep_mul(r->p, a->p, scalar);
  bn_free(scalar);
}

void ec_relic_generator(ec_relic_point_t g) {
  ep_curve_get_gen(g->p);
}

size_t ec_relic_point_size_bin(const ec_relic_point_t p, int pack) {
  return ep_size_bin(p->p, pack);
}

void ec_relic_point_write_bin(uint8_t* out, size_t len, const ec_relic_point_t p, int pack) {
  ep_write_bin(out, len, p->p, pack);
}

void ec_relic_point_read_bin(ec_relic_point_t p, const uint8_t* in, size_t len) {
  ep_read_bin(p->p, in, len);
  /* ep_read_bin leaves a decompressed point in affine form; mark it so by
   * setting the projective z coordinate to one */
  fp_zero(p->p->z);
  fp_set_dig(p->p->z, 1);
}

int ec_relic_point_coord_bin(uint8_t* xout, uint8_t* yout, size_t len, const ec_relic_point_t p) {
  ep_t affine;

  /* fp_write_bin throws ERR_NO_BUFFER unless len is exactly RLC_FP_BYTES. */
  if (len != RLC_FP_BYTES) {
    return -1;
  }

  ep_null(affine);
  ep_new(affine);
  ep_norm(affine, p->p);
  fp_write_bin(xout, len, affine->x);
  fp_write_bin(yout, len, affine->y);
  ep_free(affine);
  return 0;
}
