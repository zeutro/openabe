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
/// \file   zelement_low.h
///
/// \brief  Class definition files for a group element.
///
/// \author J. Ayo Akinyele
///

#ifndef __ZELEMENT_EC_H__
#define __ZELEMENT_EC_H__

#include <iostream>
#include <memory>

#if defined(EC_WITH_OPENSSL)
#define BN_WITH_OPENSSL
#endif

#include <openssl/ec.h>
extern "C" {
#include <openabe/zml/zelement.h>
}

int  ec_convert_to_bytestring(const ec_group_t group,
                              oabe::OpenABEByteString & s,
                              const ec_point_t p);
std::string ec_point_to_string(ec_group_t group, const ec_point_t p);

namespace oabe {

/// \class	ZP_t
/// \brief	An abstract class for integers (works wih OpenSSL and RELIC unlike ZP)
class ZP_t : public ZObject {
private:
  void getByteString(OpenABEByteString &z) const;

public:
  bignum_t m_ZP;
  bignum_t order;

  bool isInit, isOrderSet;
  ZP_t();
  ZP_t(bignum_t o);
  ZP_t(char*);
  ZP_t(uint8_t*,uint32_t);
  ZP_t(const ZP_t&);
  ~ZP_t();

  ZP_t& operator+=(const ZP_t& x);
  ZP_t& operator-=(const ZP_t& x);
  ZP_t& operator-=(int x);
  ZP_t& operator*=(const ZP_t& x);
  ZP_t& operator=(const ZP_t& w)
  {
    if (isInit) { zml_bignum_copy(this->m_ZP, w.m_ZP); }
    if (w.isOrderSet) { zml_bignum_copy(this->order, w.order); }
    else ro_error();
    return *this;
  }
  std::string getBytesAsString();
  OpenABEByteString getByteString();

  void setRandom(OpenABERNG *rng);
  void setZero();
  void set(bignum_t i);
  void setOrder(const bignum_t order);
  void multInverse();
  friend ZP_t operator-(const ZP_t&);
  friend ZP_t operator-(const ZP_t&,const ZP_t&);
  friend ZP_t operator+(const ZP_t&,const ZP_t&);
  friend ZP_t operator*(const ZP_t&,const ZP_t&);
  friend ZP_t operator/(const ZP_t&,const ZP_t&);

  friend std::ostream& operator<<(std::ostream&, const ZP_t&);
  friend bool operator<(const ZP_t& x,const ZP_t& y);
  friend bool operator<=(const ZP_t& x,const ZP_t& y);
  friend bool operator>(const ZP_t& x,const ZP_t& y);
  friend bool operator>=(const ZP_t& x,const ZP_t& y);
  friend bool operator==(const ZP_t& x,const ZP_t& y);
  friend bool operator!=(const ZP_t& x,const ZP_t& y);

  ZP_t*  clone() const { return new ZP_t(*this); }
  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
  bool isEqual(ZObject*) const;

};

// Forward declare the elliptic curve point class
class G_t;
// retrieve the group field of teh ECGroup class
#define GET_GROUP(g)	g->group

/// \class	ECGroup
/// \brief	Wrapper for managing elliptic curve groups
class ECGroup : public ZGroup {
public:
  ec_group_t   group;
  bignum_t     order;

  ECGroup(OpenABECurveID id);
  ~ECGroup();

  void getGenerator(ec_point_t g);
  void getGroupOrder(bignum_t o);
};

/// \class	G_t
/// \brief	Wrapper for ordinary elliptic curve points
class G_t : public ZObject {
public:
  ec_point_t m_G;
  std::shared_ptr<ECGroup> ecgroup;
  bool isInit;

  G_t();
  G_t(std::shared_ptr<ECGroup> ecgroup);
  G_t(const G_t& w);
  ~G_t();

  G_t& operator=(const G_t& w);
  G_t exp(ZP_t&);
  void get(ZP_t&, ZP_t&);

  friend G_t operator*(const G_t&, const G_t&);
  friend std::ostream& operator<<(std::ostream&, const G_t&);
  friend bool operator==(const G_t& x,const G_t& y) {
    if(ec_point_cmp(GET_GROUP(x.ecgroup), x.m_G, y.m_G) == G_CMP_EQ)
      return true;
    else
      return false;
  }
  friend bool operator!=(const G_t& x,const G_t& y) {
    if (ec_point_cmp(GET_GROUP(y.ecgroup), x.m_G, y.m_G) != G_CMP_EQ)
      return true;
    else return false;
  }
  G_t* clone() const { return new G_t(*this); }
  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
  bool isEqual(ZObject*) const;
};

void generateECCurveParameters(EC_GROUP **group, std::string paramid);

}

#endif	// __ZELEMENT_EC_H__




