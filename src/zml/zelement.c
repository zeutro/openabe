///
/// \file   zelement.c
///
/// \brief  Class implementation for generic ZP_t and G_t elements.
///         Works either with OpenSSL or RELIC.
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openabe/zml/zelement.h>
#include <openabe/utils/zconstants.h>

#include <openssl/objects.h>

#if defined(BP_WITH_OPENSSL)
#define EC_WITH_OPENSSL
#define BN_WITH_OPENSSL
#endif

/********************************************************************************
 * ZML abstract C operations for bignum operations
 ********************************************************************************/
void zml_init() {
#if !defined(BP_WITH_OPENSSL)
  core_init();
  ec_core_init();
#endif
}

void zml_clean() {
#if !defined(BP_WITH_OPENSSL)
  core_clean();
  ec_core_clean();
#endif
}

#if !defined(BP_WITH_OPENSSL)
int zml_check_error() {
  ctx_t *ctx = core_get();
  if (ctx != NULL) {
    if (ctx->code == STS_OK)
      return TRUE;
    else
      return FALSE; /* means there was an error */
  }
  return -1;
}
#endif

void zml_bignum_init(bignum_t *b) {
#if defined(BN_WITH_OPENSSL)
    *b = BN_new();
#else
    bn_null(*b);
    bn_new(*b);
#endif
}

void zml_bignum_copy(bignum_t to, const bignum_t from) {
#if defined(BN_WITH_OPENSSL)
  BN_copy(to, from);
#else
  bn_copy_const(to, from);
#endif
  return;
}

int zml_bignum_sign(const bignum_t a) {
#if defined(BN_WITH_OPENSSL)
    return BN_is_negative(a);
#else
    return bn_sign(a);
#endif
}

int zml_bignum_cmp(const bignum_t a, const bignum_t b) {
#if defined(BN_WITH_OPENSSL)
    return BN_cmp(a, b);
#else
    return bn_cmp(a, b);
#endif
}

void zml_bignum_setzero(bignum_t a) {
#if defined(BN_WITH_OPENSSL)
    BN_zero(a);
#else
    bn_zero(a);
#endif
}

int zml_bignum_countbytes(const bignum_t a) {
#if defined(BN_WITH_OPENSSL)
    return BN_num_bytes(a);
#else
    return bn_size_bin(a);
#endif
}

#if !defined(BN_WITH_OPENSSL)
void zml_bignum_rand(bignum_t a, bignum_t o) {
  bn_rand(a, BN_POS, bn_bits(o));
}
#endif

void zml_bignum_mod(bignum_t x, const bignum_t o) {
#if defined(BN_WITH_OPENSSL)
  BN_CTX *ctx = BN_CTX_new();
  BN_mod(x, x, o, ctx);
  BN_CTX_free(ctx);
#else
  bn_mod(x, x, o);
#endif
}

void zml_bignum_add(bignum_t r, const bignum_t x, const bignum_t y,
                const bignum_t o) {
#if defined(BN_WITH_OPENSSL)
  /* computes r = (x+y) mod o */
  BN_CTX *ctx = BN_CTX_new();
  BN_mod_add(r, x, y, o, ctx);
  BN_CTX_free(ctx);
#else
  bn_add(r, x, y);
  bn_mod(r, r, o);
#endif
  return;
}

void zml_bignum_sub(bignum_t r, const bignum_t x, const bignum_t y) {
#if defined(BN_WITH_OPENSSL)
  /* computes r = (x-y) */
  BN_sub(r, x, y);
#else
  bn_sub(r, x, y);
#endif
}

void zml_bignum_sub_order(bignum_t r, const bignum_t x, const bignum_t y,
                const bignum_t o) {
#if defined(BN_WITH_OPENSSL)
  /* computes r = (x-y) mod o */
  BN_CTX *ctx = BN_CTX_new();
  BN_mod_sub(r, x, y, o, ctx);
  BN_CTX_free(ctx);
#else
  bn_sub(r, x, y);
  if (bn_sign(r) == BN_NEG) {
    bn_add(r, r, o);
  } else {
    bn_mod(r, r, o);
  }
#endif
}

void zml_bignum_mul(bignum_t r, const bignum_t x, const bignum_t y,
                const bignum_t o) {
#if defined(BN_WITH_OPENSSL)
  /* computes r = (x*y) mod o */
  BN_CTX *ctx = BN_CTX_new();
  BN_mod_mul(r, x, y, o, ctx);
  BN_CTX_free(ctx);
#else
  bn_mul(r, x, y);
  if (bn_sign(r) == BN_NEG) {
    bn_add(r, r, o);
  } else {
    bn_mod(r, r, o);
  }
#endif
}

#if !defined(BN_WITH_OPENSSL)
int bn_is_one(const bn_t a) {
  if (a->used == 0)
    return 0; // false
  else if ((a->used == 1) && (a->dp[0] == 1))
    return 1; // true
  else
    return 0; // false
}
#endif

void zml_bignum_div(bignum_t r, const bignum_t x, const bignum_t y,
                const bignum_t o) {
  // r = (1 / y) mod o
  zml_bignum_mod_inv(r, y, o);
  if (zml_bignum_is_one(x))
    return; // return r
  // r = (r * x) mod o
  zml_bignum_mul(r, r, x, o);
}

void zml_bignum_exp(bignum_t r, const bignum_t x, const bignum_t y,
                const bignum_t o) {
  // r = (x^y) mod o
#if defined(BN_WITH_OPENSSL)
  BN_CTX *ctx = BN_CTX_new();
  BN_mod_exp(r, x, y, o, ctx);
  BN_CTX_free(ctx);
#else
  bn_mxp(r, x, y, o);
#endif
}

void zml_bignum_lshift(bignum_t r, const bignum_t a, int n) {
#if defined(BN_WITH_OPENSSL)
  BN_lshift(r, a, n);
#else
  bn_lsh(r, a, n);
#endif
}

void zml_bignum_rshift(bignum_t r, const bignum_t a, int n) {
#if defined(BN_WITH_OPENSSL)
  BN_rshift(r, a, n);
#else
  bn_rsh(r, a, n);
#endif
}

char *zml_bignum_toHex(const bignum_t b, int *length) {
  char *hex = NULL;
#if defined(BN_WITH_OPENSSL)
  hex = BN_bn2hex(b);
  *length = strlen((const char *)hex);
#else
  *length = bn_size_str(b, 16);
  hex = (char *)malloc(*length+1);
  MALLOC_CHECK_OUT_OF_MEMORY(hex);
  bn_write_str(hex, *length, b, 16);
#endif
  return hex;
}

char *zml_bignum_toDec(const bignum_t b, int *length) {
  char *dec = NULL;
#if defined(BN_WITH_OPENSSL)
  dec = BN_bn2dec(b);
  *length = strlen(dec);
#else
  *length = bn_size_str(b, 10);
  dec = (char *)malloc(*length+1);
  MALLOC_CHECK_OUT_OF_MEMORY(dec);
  bn_write_str(dec, *length, b, 10);
#endif
  return dec;
}

void zml_bignum_negate(bignum_t b, const bignum_t o) {
#if defined(BN_WITH_OPENSSL)
  // 0 for +, != 0 for -
  BN_set_negative(b, -1);
  if (BN_is_negative(b)) {
    BN_add(b, b, o);
  }
#else
  bn_neg(b, b);
  if (bn_sign(b) == BN_NEG) {
    bn_add(b, b, o);
  }
#endif
}

int zml_bignum_mod_inv(bignum_t a, const bignum_t b, const bignum_t o) {
#if defined(BN_WITH_OPENSSL)
  BN_CTX *ctx = BN_CTX_new();
  BN_mod_inverse(a, b, o, ctx);
  BN_CTX_free(ctx);
  return 1;
#else
  bn_t s;
  bn_inits(s);
  // computes (1 / b) mod o
  bn_gcd_ext(s, a, NULL, b, o);
  // check if negative
  if (bn_sign(a) == BN_NEG) {
    bn_add(a, a, o);
  }
  bn_free(s);
  return 1;
#endif
}

/********************************************************************************
 * ZML abstract C operations for EC operations
 ********************************************************************************/

int ec_group_init(ec_group_t *group, uint8_t id) {
  switch (id) {
#if defined(EC_WITH_OPENSSL)
  case OpenABE_NIST_P256_ID:
      *group = EC_GROUP_new_by_curve_name(OBJ_sn2nid("prime256v1"));
      break;
  case OpenABE_NIST_P384_ID:
      *group = EC_GROUP_new_by_curve_name(OBJ_sn2nid("secp384r1"));
      break;
  case OpenABE_NIST_P521_ID:
      *group = EC_GROUP_new_by_curve_name(OBJ_sn2nid("secp521r1"));
      break;
#else /* RELIC -- group is always NULL b/c parameters are statically defined   \
         */
  case OpenABE_NIST_P256_ID:
    ec_ep_param_set(NIST_P256);
    break;
  case OpenABE_NIST_P384_ID:
    ec_ep_param_set(NIST_P384);
    break;
  case OpenABE_NIST_P521_ID:
    ec_ep_param_set(NIST_P521);
    break;
#endif
  default:
      return -1;
  }
  return 0;
}

void ec_get_order(ec_group_t group, bignum_t order) {
#if defined(EC_WITH_OPENSSL)
  EC_GROUP_get_order(group, order, NULL);
#else
  // EC group structure is defined as static vars in RELIC
  ec_ep_curve_get_ord(order);
#endif
}

void ec_point_init(ec_group_t group, ec_point_t *e) {
#if defined(EC_WITH_OPENSSL)
  *e = EC_POINT_new(group);
#else
  ep_null(*e);
  ep_new(*e);
#endif
}

void ec_point_copy(ec_point_t to, const ec_point_t from) {
#if defined(EC_WITH_OPENSSL)
  EC_POINT_copy(to, from);
#else
  ep_copy_const(to, from);
#endif
}

void ec_point_set_inf(ec_group_t group, ec_point_t p) {
#if defined(EC_WITH_OPENSSL)
  EC_POINT_set_to_infinity(group, p);
#else
  ec_ep_set_infty(p);
#endif
}

int ec_point_is_inf(ec_group_t group, ec_point_t p) {
#if defined(EC_WITH_OPENSSL)
  return (EC_POINT_is_at_infinity(group, p) == 1);
#else
  // 1 if the point is at infinity, 0 otherise.
  return ec_ep_is_infty(p);
#endif
}

int ec_point_is_on_curve(ec_group_t group, ec_point_t p) {
#if defined(EC_WITH_OPENSSL)
  int ret = EC_POINT_is_on_curve(group, p, NULL);
  return ret;
#else
  if (ec_ep_is_valid(p))
    return 1;
#endif
  return 0;
}

void ec_point_add(ec_group_t g, ec_point_t r, const ec_point_t x,
                  const ec_point_t y) {
#if defined(EC_WITH_OPENSSL)
  EC_POINT_add(g, r, x, y, NULL);
#else
  ep_add(r, x, y);
  ec_ep_norm(r, r);
#endif
}

void ec_point_mul(ec_group_t g, ec_point_t r, const ec_point_t x,
                  const bignum_t y) {
#if defined(EC_WITH_OPENSSL)
  EC_POINT_mul(g, r, NULL, x, y, NULL);
#else
  //ep_mul(r, x, y);
  ec_ep_mul_lwnaf(r, x, y);
#endif
}

int ec_point_cmp(ec_group_t group, const ec_point_t a, const ec_point_t b) {
#if defined(EC_WITH_OPENSSL)
  return EC_POINT_cmp(group, a, b, NULL);
#else
  return ec_ep_cmp(a, b);
#endif
}

void ec_get_coordinates(ec_group_t group, bignum_t x, bignum_t y,
                        const ec_point_t p) {
#if defined(EC_WITH_OPENSSL)
  EC_POINT_get_affine_coordinates_GFp(group, p, x, y, NULL);
#else
  ec_fp_prime_back(x, p->x);
  ec_fp_prime_back(y, p->y);
#endif
  return;
}

void ec_get_generator(ec_group_t group, ec_point_t p) {
#if defined(EC_WITH_OPENSSL)
  EC_POINT_copy(p, EC_GROUP_get0_generator(group));
#else
  ec_ep_curve_get_gen(p);
#endif
}

#if !defined(EC_WITH_OPENSSL)
size_t ec_point_elem_len(const ec_point_t g) {
  return ec_ep_size_bin(g, COMPRESS);
}

void ec_point_elem_in(ec_point_t g, uint8_t *in, size_t len) {
  ec_ep_read_bin(g, in, (int)len);
  ec_fp_zero(g->z);
  ec_fp_set_dig(g->z, 1);
}

void ec_point_elem_out(const ec_point_t g, uint8_t *out, size_t len) {
  ec_ep_write_bin(out, len, g, COMPRESS);
}
#endif

int ec_convert_to_point(ec_group_t group, ec_point_t p, uint8_t *xstr,
                         int len) {
#if defined(EC_WITH_OPENSSL)
  EC_POINT_oct2point(group, p, xstr, len, NULL);
  if (!EC_POINT_is_on_curve(group, p, NULL)) {
      return FALSE;
  }
  return TRUE;
#else
  ec_point_elem_in(p, xstr, len);
  return TRUE;
#endif
}


int bp_group_init(bp_group_t *group, uint8_t id) {
#if !defined(BP_WITH_OPENSSL)
  /* RELIC definitions */
  int twist = EP_DTYPE; // , degree = 2;
#endif
  switch (id) {
#if defined(BP_WITH_OPENSSL)
  case OpenABE_BN_P254_ID:
    *group = BP_GROUP_new_by_curve_name(NID_fp254bnb);
    break;
  case OpenABE_BN_P256_ID:
    *group = NULL;
    return -1;
    break;
//    *group = BP_GROUP_new_by_curve_name(NID_fp256bnb);
//    break;
#else /* RELIC -- group is always NULL b/c parameters are statically defined   \
         */
  case OpenABE_BN_P254_ID:
    ep_param_set(BN_P254);
    ep2_curve_set_twist(twist);
    break;
  case OpenABE_BN_P256_ID:
    ep_param_set(BN_P256);
    ep2_curve_set_twist(twist);
    break;
  case OpenABE_BN_P382_ID:
    ep_param_set(BN_P382);
    ep2_curve_set_twist(twist);
    break;
#endif
  default:
      return -1;
  }
  return 0;
}

void bp_get_order(bp_group_t group, bignum_t order) {
#if defined(BP_WITH_OPENSSL)
  BP_GROUP_get_order(group, order, NULL);
#else
  // EC group structure is defined as static vars in RELIC
  // assumes we've called bp_group_init on 'group'
  // g1_get_ord
  ep_curve_get_ord(order);
#endif
}

/********************************************************************************
 * ZML abstract C operations for G1 init/arithmetic
 ********************************************************************************/

void g1_init(bp_group_t group, g1_ptr *e) {
#if defined(BP_WITH_OPENSSL)
  *e = G1_ELEM_new(group);
#else
  g1_inits(*e);
#endif
}

void g1_set_to_infinity(bp_group_t group, g1_ptr *e) {
#if defined(BP_WITH_OPENSSL)
  *e = G1_ELEM_new(group);
  G1_ELEM_set_to_infinity(group, *e);
#else
  g1_inits(*e);
  g1_set_infty(*e);
#endif
}

void g1_add_op(bp_group_t group, g1_ptr z, const g1_ptr x, const g1_ptr y) {
#if defined(BP_WITH_OPENSSL)
  G1_ELEM_add(group, z, x, y, NULL);
#else
  ep_add_projc(z, x, y);
  ep_norm(z, z);
#endif
}

void g1_sub_op(bp_group_t group, g1_ptr z, const g1_ptr x) {
#if defined(BP_WITH_OPENSSL)
  int rc = G1_ELEM_invert(group, z, NULL);
  if (rc == 1) {
      G1_ELEM_add(group, z, x, z, NULL);
  }
#else
  ep_sub_projc(z, x, z);
  ep_norm(z, z);
#endif

}

void g1_mul_op(bp_group_t group, g1_ptr z, const g1_ptr x, const bignum_t r) {
#if defined(BP_WITH_OPENSSL)
  G1_ELEM_mul(group, z, NULL, x, r, NULL);
#else
  g1_mul(z, x, r);
#endif
}

#if !defined(BP_WITH_OPENSSL)
void g1_rand_op(g1_ptr g) {
    ep_rand(g);
}
#endif

#if defined(BP_WITH_OPENSSL)
static int g1_map_OpenSSL(const bp_group_t group, uint8_t *h, int hlen,
                           g1_ptr p) {
  int result = FALSE;
  bignum_t px;

  px = BN_new();
  BN_bin2bn(h, hlen, px);
  while (TRUE) {
    if (G1_ELEM_set_compressed_coordinates(group, p, px, 0, NULL) == 1) {
      // Found a y-coordinate. Now verify that x/y is on the curve
      if (G1_ELEM_is_on_curve(group, p, NULL) == 1) {
        result = TRUE;
        break;
      }
    }
    BN_add(px, px, BN_value_one());
  }

  BN_free(px);
  return result;
}
#endif

void g1_map_op(const bp_group_t group, g1_ptr g, uint8_t *msg, int msg_len) {
#if defined(BP_WITH_OPENSSL)
  // now convert digest into a G1 point
  g1_map_OpenSSL(group, msg, msg_len, g);
#else
  g1_map(g, msg, msg_len);
#endif
}

#if !defined(BP_WITH_OPENSSL)
size_t g1_elem_len(const g1_ptr g) {
  return ep_size_bin(g, COMPRESS);
}

void g1_elem_in(g1_ptr g, uint8_t *in, size_t len) {
    ep_read_bin(g, in, (int)len);
}

void g1_elem_out(const g1_ptr g, uint8_t *out, size_t len) {
  ep_write_bin(out, len, g, COMPRESS);
}

size_t g2_elem_len(g2_ptr g) {
  return ep2_size_bin(g, COMPRESS);
}

void g2_elem_in(g2_ptr g, uint8_t *in, size_t len) {
    ep2_read_bin(g, in, (int)len);
}

void g2_elem_out(g2_ptr g, uint8_t *out, size_t len) {
  ep2_write_bin(out, len, g, COMPRESS);
}

size_t gt_elem_len(gt_ptr g, int should_compress) {
  return fp12_size_bin(g, should_compress);
}

void gt_elem_in(gt_ptr g, uint8_t *in, size_t len) {
    fp12_read_bin(g, in, (int)len);
}

void gt_elem_out(gt_ptr g, uint8_t *out, size_t len, int should_compress) {
  fp12_write_bin(out, len, g, should_compress);
}

#endif

/********************************************************************************
 * ZML abstract C operations for G2 init/arithmetic
 ********************************************************************************/

void g2_init(bp_group_t group, g2_ptr *e) {
#if defined(BP_WITH_OPENSSL)
  *e = G2_ELEM_new(group);
#else
  ep2_inits(*e);
#endif
}

void g2_set_to_infinity(bp_group_t group, g2_ptr *e) {
#if defined(BP_WITH_OPENSSL)
  *e = G2_ELEM_new(group);
  G2_ELEM_set_to_infinity(group, *e);
#else
  ep2_inits(*e);
  // g2_set_infty
  ep2_set_infty(*e);
#endif
}

void g2_mul_op(bp_group_t group, g2_ptr z, g2_ptr x, bignum_t r) {
#if defined(BP_WITH_OPENSSL)
  G2_ELEM_mul(group, z, NULL, x, r, NULL);
#else
  // g2_mul(z, x, r);
  ep2_mul_lwnaf(z, x, r);
#endif
}

int g2_cmp_op(bp_group_t group, g2_ptr x, g2_ptr y) {
#if defined(BP_WITH_OPENSSL)
    return G2_ELEM_cmp(group, x, y, NULL);
#else
    return ep2_cmp(x, y);
#endif
}

/********************************************************************************
 * abstract C operations for GT init/arithmetic
 ********************************************************************************/

void gt_init(const bp_group_t group, gt_ptr *e) {
#if defined(BP_WITH_OPENSSL)
  *e = GT_ELEM_new(group);
#else
  fp12_inits(*e);
#endif
}

void gt_set_to_infinity(bp_group_t group, gt_ptr *e) {
#if defined(BP_WITH_OPENSSL)
  *e = GT_ELEM_new(group);
  GT_ELEM_set_to_unity(group, *e);
#else
  fp12_inits(*e);
  // gt_set_unity
  fp12_set_dig(*e, 1);
#endif
}

void gt_mul_op(const bp_group_t group, gt_ptr z, gt_ptr x, gt_ptr y) {
#if defined(BP_WITH_OPENSSL)
  GT_ELEM_mul(group, z, x, y, NULL);
#else
  fp12_mul_lazyr(z, x, y);
#endif
}

void gt_div_op(const bp_group_t group, gt_ptr z, gt_ptr x, gt_ptr y) {
#if defined(BP_WITH_OPENSSL)
  GT_ELEM_inv(group, z, y, NULL);
  GT_ELEM_mul(group, z, x, z, NULL);
#else
  // gt_inv
  fp12_inv(z, y);
  // gt_mul
  fp12_mul_lazyr(z, x, z);
#endif
}

void gt_exp_op(const bp_group_t group, gt_ptr y, gt_ptr x, bignum_t r) {
#if defined(BP_WITH_OPENSSL)
  GT_ELEM_exp(group, y, x, r, NULL);
#else
  fp12_exp(y, x, r);
#endif
}

int gt_is_unity_check(const bp_group_t group, gt_ptr r) {
#if defined(BP_WITH_OPENSSL)
  return (GT_ELEM_is_unity(group, r) == 1);
#else
  // gt_is_unity
  return (fp12_cmp_dig(r, 1)) == 0;
#endif
}

void bp_map_op(const bp_group_t group, gt_ptr gt, g1_ptr g1, g2_ptr g2) {
#if defined(BP_WITH_OPENSSL)
  GT_ELEM_pairing(group, gt, g1, g2, NULL);
#else
  pp_map_oatep_k12(gt, g1, g2);
#endif
}

#if !defined(BP_WITH_OPENSSL)
/****************************************************************
 * RELIC helper functions
 * These may end up as part of RELIC, not the OpenABE.
 * Once testing is complete they could be moved into the RELIC
 * source code and released per LGPL terms. It's not really clear
 * what to do with them.
 ****************************************************************/

void bn_copy_const(bn_t c, const bn_t a) {
    int i;

    if (c->dp == a->dp)
        return;

    bn_grow(c, a->used);

    for (i = 0; i < a->used; i++) {
        c->dp[i] = a->dp[i];
    }

    c->used = a->used;
    c->sign = a->sign;
}

void ep_copy_const(ep_t r, const ep_t p) {
    fp_copy_const(r->x, p->x);
    fp_copy_const(r->y, p->y);
    fp_copy_const(r->z, p->z);
    r->norm = p->norm;
}

void fp_copy_const(fp_t c, const fp_t a) {
    int i;
    for (i = 0; i < FP_DIGS; i++) {
            c[i] = a[i];
    }
}

void ep2_copy_const(ep2_t r, const ep2_t p) {
    fp2_copy_const(r->x, p->x);
    fp2_copy_const(r->y, p->y);
    fp2_copy_const(r->z, p->z);
    r->norm = p->norm;
}

void fp2_copy_const(fp2_t c, const fp2_t a) {
    fp_copy_const(c[0], a[0]);
    fp_copy_const(c[1], a[1]);
}

void fp12_copy_const(fp12_t c, const fp12_t a) {
    fp6_copy_const(c[0], a[0]);
    fp6_copy_const(c[1], a[1]);
}

void fp6_copy_const(fp6_t c, const fp6_t a) {
    fp2_copy_const(c[0], a[0]);
    fp2_copy_const(c[1], a[1]);
    fp2_copy_const(c[2], a[2]);
}

int bn_cmp_const(bn_t a, const bn_t b) {
    if (a->sign == BN_POS && b->sign == BN_NEG) {
        return CMP_GT;
    }
    if (a->sign == BN_NEG && b->sign == BN_POS) {
        return CMP_LT;
    }

    if (a->sign == BN_NEG) {
        return bn_cmp_abs_const(b, a);
    }

    return bn_cmp_abs_const(a, b);
}

int bn_cmp_abs_const(const bn_t a, const bn_t b) {
    if (a->used > b->used) {
        return CMP_GT;
    }

    if (a->used < b->used) {
        return CMP_LT;
    }

    return bn_cmpn_low_const(a->dp, b->dp, a->used);
}

int bn_cmpn_low_const(const dig_t *a, const dig_t *b, const int size) {
    int i, r;

    a += (size - 1);
    b += (size - 1);

    r = CMP_EQ;
    for (i = 0; i < size; i++, --a, --b) {
        if (*a != *b && r == CMP_EQ) {
            r = (*a > *b ? CMP_GT : CMP_LT);
        }
    }
    return r;
}


int ep_cmp_const(ep_t p, const ep_t q) {
    if (fp_cmp_const(p->x, q->x) != CMP_EQ) {
        return CMP_NE;
    }

    if (fp_cmp_const(p->y, q->y) != CMP_EQ) {
        return CMP_NE;
    }

    if (fp_cmp_const(p->z, q->z) != CMP_EQ) {
        return CMP_NE;
    }

    return CMP_EQ;
}

int ep2_cmp_const(ep2_t p, const ep2_t q) {
    if (fp2_cmp_const(p->x, q->x) != CMP_EQ) {
        return CMP_NE;
    }

    if (fp2_cmp_const(p->y, q->y) != CMP_EQ) {
        return CMP_NE;
    }

    if (fp2_cmp_const(p->z, q->z) != CMP_EQ) {
        return CMP_NE;
    }

    return CMP_EQ;
}

int fp12_cmp_const(fp12_t a, const fp12_t b) {
    return ((fp6_cmp_const(a[0], b[0]) == CMP_EQ) &&
            (fp6_cmp_const(a[1], b[1]) == CMP_EQ) ? CMP_EQ : CMP_NE);
}

int fp6_cmp_const(fp6_t a, const fp6_t b) {
    return ((fp2_cmp_const(a[0], b[0]) == CMP_EQ) && (fp2_cmp_const(a[1], b[1]) == CMP_EQ)
            && (fp2_cmp_const(a[2], b[2]) == CMP_EQ) ? CMP_EQ : CMP_NE);
}

int fp2_cmp_const(fp2_t a, const fp2_t b) {
    return (fp_cmp_const(a[0], b[0]) == CMP_EQ) &&
    (fp_cmp_const(a[1], b[1]) == CMP_EQ) ? CMP_EQ : CMP_NE;
}

int fp_cmp_const(fp_t a, const fp_t b) {
    return fp_cmpn_low_const(a, b);
}

int fp_cmpn_low_const(dig_t *a, const dig_t *b) {
    int i, r;

    a += (FP_DIGS - 1);
    b += (FP_DIGS - 1);

    r = CMP_EQ;
    for (i = 0; i < FP_DIGS; i++, --a, --b) {
        if (*a != *b && r == CMP_EQ) {
            r = (*a > *b ? CMP_GT : CMP_LT);
        }
    }
    return r;
}

#endif
