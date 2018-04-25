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
/// \file   zelement_ec.cpp
///
/// \brief  Class implementation for generic ZP_t and G_t elements.
///         Works either with OpenSSL or RELIC.
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <openabe/openabe.h>

extern "C" {
#include <openabe/zml/zelement.h>
}

using namespace std;
using namespace oabe;

string ec_point_to_string(ec_group_t group, const ec_point_t p) {
  bignum_t x, y;
  zml_bignum_init(&x);
  zml_bignum_init(&y);
  ec_get_coordinates(group, x, y, p);
  int x_size, y_size;
  char *xstr = zml_bignum_toDec(x, &x_size);
  char *ystr = zml_bignum_toDec(y, &y_size);
  string s;
  s = "[" + string(xstr, x_size);
  s += ",";
  s += string(ystr, y_size) + "]";

  zml_bignum_safe_free(xstr);
  zml_bignum_safe_free(ystr);
  zml_bignum_free(x);
  zml_bignum_free(y);
  return s;
}

int ec_convert_to_bytestring(const ec_group_t group, oabe::OpenABEByteString &s,
                             const ec_point_t p) {
#if defined(EC_WITH_OPENSSL)
  BN_CTX *ctx = BN_CTX_new();
  uint8_t buf[MAX_BUFFER_SIZE];
  memset(buf, 0, MAX_BUFFER_SIZE);
  size_t len = EC_POINT_point2oct(group, p, POINT_CONVERSION_COMPRESSED, buf,
                                  MAX_BUFFER_SIZE, ctx);
  s.appendArray(buf, len);
  BN_CTX_free(ctx);
  return (int)len;
#else
  size_t len = ec_point_elem_len(p);
  uint8_t buf[len + 1];
  ec_point_elem_out(p, buf, len);
  s.appendArray(buf, len);
  return (int)len;
#endif
}

/********************************************************************************
 * Implementation of the ZP class
 ********************************************************************************/
namespace oabe {

void generateECCurveParameters(EC_GROUP **group, string paramid) {
  if (*group == NULL) {
    // obtain the nid from the paramid
    int nid = OpenABE_convertStringToNID(paramid);
    if (nid == 0) {
      throw OpenABE_ERROR_INVALID_INPUT;
    }
    // construct the group by nid
    *group = EC_GROUP_new_by_curve_name(nid);

    ASSERT_NOTNULL(*group);
  }
}

ZP_t::ZP_t() : ZObject() {
  zml_bignum_init(&this->m_ZP);
  zml_bignum_init(&this->order);
  this->isInit = true;
  this->isOrderSet = false;
}

ZP_t::ZP_t(bignum_t order) {
  zml_bignum_init(&this->m_ZP);
  zml_bignum_init(&this->order);
  zml_bignum_copy(this->order, order);
  this->isInit = true;
  this->isOrderSet = true;
}

ZP_t::ZP_t(const ZP_t &w) {
  zml_bignum_init(&this->m_ZP);
  zml_bignum_init(&this->order);

  this->isInit = true;
  zml_bignum_copy(this->m_ZP, w.m_ZP);
  if (w.isOrderSet) {
    zml_bignum_copy(this->order, w.order);
  }
  this->isOrderSet = w.isOrderSet;
}

ZP_t::~ZP_t() {
    zml_bignum_free(this->m_ZP);
    zml_bignum_free(this->order);
}

ZP_t::ZP_t(char *str) {
  zml_bignum_init(&this->m_ZP);
  isInit = true;
  zml_bignum_fromHex(this->m_ZP, (const char *)str, strlen(str));
  this->isOrderSet = false;
}

ZP_t::ZP_t(uint8_t *bstr, uint32_t bstr_len) {
  zml_bignum_init(&this->m_ZP);
  isInit = true;
  zml_bignum_fromBin(this->m_ZP, bstr, bstr_len);
  this->isOrderSet = false;
}

ZP_t &ZP_t::operator+=(const ZP_t &x) {
  *this = *this + x;
  return *this;
}

ZP_t &ZP_t::operator-=(const ZP_t &x) {
  *this = *this - x;
  return *this;
}

ZP_t &ZP_t::operator-=(int x) {
  // subtract x from whatever is in m_ZP (no modulo op though)
  if (this->isInit) {
    // ZP_t X(x);
    bignum_t X;
    zml_bignum_init(&X);
    zml_bignum_setuint(X, x);
    zml_bignum_sub(this->m_ZP, this->m_ZP, X);
    zml_bignum_free(X);
  }
  return *this;
}

ZP_t &ZP_t::operator*=(const ZP_t &x) {
  *this = *this * x;
  return *this;
}

ZP_t operator+(const ZP_t &x, const ZP_t &y) {
  ASSERT(x.isOrderSet || y.isOrderSet, OpenABE_ERROR_INVALID_INPUT);
  ZP_t zr;
  if (x.isOrderSet)
    zr.setOrder(x.order);
  else
    zr.setOrder(y.order);

  zml_bignum_add(zr.m_ZP, x.m_ZP, y.m_ZP, zr.order);
  return zr;
}

ZP_t operator-(const ZP_t &x, const ZP_t &y) {
  ASSERT(x.isOrderSet || y.isOrderSet, OpenABE_ERROR_INVALID_INPUT);
  ZP_t zr;
  if (x.isOrderSet)
    zr.setOrder(x.order);
  else
    zr.setOrder(y.order);

  zml_bignum_sub_order(zr.m_ZP, x.m_ZP, y.m_ZP, zr.order);
  return zr;
}

ZP_t operator-(const ZP_t &x) {
  ASSERT(x.isInit && x.isOrderSet, OpenABE_ERROR_INVALID_INPUT);
  ZP_t zr = x;
  zml_bignum_negate(zr.m_ZP, zr.order);
  return zr;
}

ZP_t operator*(const ZP_t &x, const ZP_t &y) {
  ASSERT(x.isOrderSet || y.isOrderSet, OpenABE_ERROR_INVALID_INPUT);
  ZP_t zr;
  if (x.isOrderSet)
    zr.setOrder(x.order);
  else
    zr.setOrder(y.order);

  zml_bignum_mul(zr.m_ZP, x.m_ZP, y.m_ZP, zr.order);
  return zr;
}

void ZP_t::multInverse() {
  // compute c = (1 / zr) mod o
  if (this->isInit && this->isOrderSet) {
    ASSERT(zml_bignum_mod_inv(this->m_ZP, this->m_ZP, this->order),
           OpenABE_ERROR_INVALID_INPUT);
  }
}

ZP_t operator/(const ZP_t &x, const ZP_t &y) {
  if (zml_bignum_is_zero(y.m_ZP)) {
    cout << "Divide by zero error!" << endl;
    throw OpenABE_ERROR_DIVIDE_BY_ZERO;
  }
  ASSERT(x.isOrderSet || y.isOrderSet, OpenABE_ERROR_INVALID_INPUT);
  ZP_t r;
  if (x.isOrderSet)
    r.setOrder(x.order);
  else
    r.setOrder(y.order);

  zml_bignum_div(r.m_ZP, x.m_ZP, y.m_ZP, r.order);
  return r;
}

void ZP_t::set(bignum_t i) {
  if (this->isInit) {
    zml_bignum_copy(this->m_ZP, i);
  }
}

void ZP_t::setZero() {
  if (this->isInit) {
    zml_bignum_setzero(this->m_ZP);
  }
}

void ZP_t::setOrder(const bignum_t order) {
  if (!this->isOrderSet) {
    zml_bignum_copy(this->order, order);
    if (this->isInit) {
      zml_bignum_mod(this->m_ZP, this->order);
    }
  }
  return;
}

void ZP_t::setRandom(OpenABERNG *rng) {
  if (this->isInit && this->isOrderSet) {
    // 1. get some number of bytes
    int length = zml_bignum_countbytes(this->order);
    // 2. call bignum_fromBin on the bytes obtained
    uint8_t buf[length];
    memset(buf, 0, length);
    rng->getRandomBytes(buf, length);
    zml_bignum_fromBin(this->m_ZP, buf, length);
    zml_bignum_mod(this->m_ZP, this->order);
  } else {
    throw OpenABE_ERROR_ELEMENT_NOT_INITIALIZED;
  }
}

bool operator<(const ZP_t &x, const ZP_t &y) {
  return (zml_bignum_cmp(x.m_ZP, y.m_ZP) == BN_CMP_LT);
}

bool operator<=(const ZP_t &x, const ZP_t &y) {
  return (zml_bignum_cmp(x.m_ZP, y.m_ZP) <= BN_CMP_EQ);
}

bool operator>(const ZP_t &x, const ZP_t &y) {
  return (zml_bignum_cmp(x.m_ZP, y.m_ZP) == BN_CMP_GT);
}

bool operator>=(const ZP_t &x, const ZP_t &y) {
  return (zml_bignum_cmp(x.m_ZP, y.m_ZP) >= BN_CMP_EQ);
}

bool operator==(const ZP_t &x, const ZP_t &y) {
  ASSERT(x.isOrderSet || y.isOrderSet, OpenABE_ERROR_ELEMENT_NOT_INITIALIZED);
  return (zml_bignum_cmp(x.m_ZP, y.m_ZP) == BN_CMP_EQ);
}

bool operator!=(const ZP_t &x, const ZP_t &y) {
  return (zml_bignum_cmp(x.m_ZP, y.m_ZP) != BN_CMP_EQ);
}

ostream &operator<<(ostream &s, const ZP_t &zr) {
  if (zr.isInit) {
    int len = 0;
    char *str = zml_bignum_toDec(zr.m_ZP, &len);
    string s0 = string(str, len);
    zml_bignum_safe_free(str);
    s << s0;
  }

  return s;
}

void ZP_t::serialize(OpenABEByteString &result) const {
  if (this->isInit) {
    result.clear();
    result.insertFirstByte(OpenABE_ELEMENT_ZP_t);
    this->getByteString(result);
  }
}

void ZP_t::deserialize(OpenABEByteString &input) {
  size_t inputSize = input.size(), hdrLen = 3;

  if (this->isInit) {
    // first byte is the group type
    if (input.at(0) == OpenABE_ELEMENT_ZP_t && inputSize > hdrLen) {
      uint16_t len = 0;
      // read 2 bytes from right to left
      len |= input.at(2);             // Moves to 0x00FF
      len |= (input.at(1) << 8);      // Moves to 0xFF00
      // cout << "len: " << len << ", input size: " << input.size() << endl;
      ASSERT(input.size() == (len + hdrLen), OpenABE_ERROR_SERIALIZATION_FAILED);

      uint8_t *bstr = (input.getInternalPtr() + hdrLen);
      zml_bignum_fromBin(this->m_ZP, bstr, len);
    }
  }
}

bool ZP_t::isEqual(ZObject *z) const {
  ZP_t *z1 = dynamic_cast<ZP_t *>(z);
  if (z1 != NULL) {
    return *z1 == *this;
  }
  return false;
}

string ZP_t::getBytesAsString() {
  int len = 0;
  if (this->isInit) {
    char *str = zml_bignum_toHex(this->m_ZP, &len);
    string s0 = string(str, len);
    zml_bignum_safe_free(str);
    return s0;
  } else {
    throw OpenABE_ERROR_ELEMENT_NOT_INITIALIZED;
  }
}

OpenABEByteString ZP_t::getByteString() {
  int length = zml_bignum_countbytes(this->m_ZP);

  uint8_t data[length];
  memset(data, 0, length);
  zml_bignum_toBin(this->m_ZP, data, length);

  OpenABEByteString z;
  z.appendArray(data, length);
  return z;
}

// used specifically for serialization
void ZP_t::getByteString(OpenABEByteString &z) const {
  int length = zml_bignum_countbytes(this->m_ZP);

  uint8_t data[length];
  memset(data, 0, length);
  zml_bignum_toBin(this->m_ZP, data, length);

  z.pack16bits((uint16_t)length);
  z.appendArray(data, length);
}

/********************************************************************************
 * Implementation of the ECGroup class
 ********************************************************************************/

ECGroup::ECGroup(OpenABECurveID id) : ZGroup(id) {
  ec_group_init(&group, id);
  this->group_param = OpenABE_convertCurveIDToString(id);
  zml_bignum_init(&order);
  ec_get_order(group, order);
}

ECGroup::~ECGroup() {
  ec_group_free(group);
  zml_bignum_free(order);
}

void ECGroup::getGenerator(ec_point_t g) { ec_get_generator(group, g); }

void ECGroup::getGroupOrder(bignum_t o) { zml_bignum_copy(o, order); }

/********************************************************************************
 * Implementation of the G_t class
 ********************************************************************************/

G_t::G_t() {
  this->isInit = true;
  this->ecgroup = nullptr;
  ec_point_set_null(this->m_G);
}

G_t::G_t(std::shared_ptr<ECGroup> ecgroup) {
  this->isInit = true;
  this->ecgroup = ecgroup;
  ec_point_init(GET_GROUP(this->ecgroup), &this->m_G);
  ec_point_set_inf(GET_GROUP(this->ecgroup), this->m_G);
}

G_t::G_t(const G_t &w) {
  this->isInit = true;
  if (w.ecgroup != nullptr) {
    this->ecgroup = w.ecgroup;
  } else {
    throw OpenABE_ERROR_INVALID_GROUP_PARAMS;
  }
  ec_point_init(GET_GROUP(this->ecgroup), &this->m_G);
  ec_point_copy(this->m_G, w.m_G);
}

G_t &G_t::operator=(const G_t &w) {
  if (isInit == true) {
    ec_point_copy(this->m_G, w.m_G);
    if (w.ecgroup != nullptr) {
      this->ecgroup = w.ecgroup;
    }
  } else
    ro_error();
  return *this;
}

G_t::~G_t() {
  if (this->isInit) {
    ec_point_free(this->m_G);
    this->isInit = false;
  }
}

G_t operator*(const G_t &x, const G_t &y) {
  G_t z(x.ecgroup);
  ec_point_add(GET_GROUP(z.ecgroup), z.m_G, x.m_G, y.m_G);
  return z;
}

G_t G_t::exp(ZP_t &z) {
  G_t g(this->ecgroup);
  ec_point_mul(GET_GROUP(g.ecgroup), g.m_G, this->m_G, z.m_ZP);
  return g;
}

void G_t::get(ZP_t &X, ZP_t &Y) {
  if (this->isInit) {
    ec_get_coordinates(GET_GROUP(this->ecgroup), X.m_ZP, Y.m_ZP, this->m_G);
  }
}

ostream &operator<<(ostream &os, const G_t &g) {
  os << ec_point_to_string(GET_GROUP(g.ecgroup), g.m_G);
  return os;
}

void G_t::serialize(OpenABEByteString &result) const {
  OpenABEByteString ss;
  string str;
  size_t total_len;

  if (this->isInit) {
    result.clear();
    result.insertFirstByte(OpenABE_ELEMENT_G_t);
    total_len =
        ec_convert_to_bytestring(GET_GROUP(this->ecgroup), ss, this->m_G);
    // cout << "len: " << ss.size() << ", total_len: " << total_len << endl;
    ASSERT(ss.size() == total_len, OpenABE_ERROR_SERIALIZATION_FAILED);
    result.pack16bits((uint16_t)total_len);
    result += ss;
    ss.clear();
  } else {
    /* throw an error */
    throw OpenABE_ERROR_ELEMENT_NOT_INITIALIZED;
  }
}

void G_t::deserialize(OpenABEByteString &input) {
  size_t inputSize = input.size(), hdrLen = 3;

  if (this->isInit && this->ecgroup != nullptr) {
    // first byte is the group type
    if (input.at(0) == OpenABE_ELEMENT_G_t && inputSize > hdrLen) {
      uint16_t len = 0;
      // read 2 bytes from right to left
      len |= input.at(2);                // Moves to 0x00FF
      len |= (input.at(1) << 8);         // Moves to 0xFF00
      ASSERT(input.size() == (len + hdrLen), OpenABE_ERROR_SERIALIZATION_FAILED);

      uint8_t *pointstr = (input.getInternalPtr() + hdrLen);
      if (is_ec_point_null(this->m_G)) {
        ec_point_init(GET_GROUP(this->ecgroup), &this->m_G);
      }
      ec_convert_to_point(GET_GROUP(this->ecgroup), this->m_G, pointstr, len);
    }
  } else {
    throw OpenABE_ERROR_ELEMENT_NOT_INITIALIZED;
  }
}

bool G_t::isEqual(ZObject *z) const {
  G_t *z1 = dynamic_cast<G_t *>(z);
  if (z1 != NULL) {
    return *z1 == *this;
  }
  return false;
}

}
