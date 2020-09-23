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
/// \file   zelement_bp.h
///
/// \brief  Class definition for a group element.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZELEMENT_BP_H__
#define __ZELEMENT_BP_H__

#if defined(BP_WITH_OPENSSL)
#define BN_WITH_OPENSSL
#define EC_WITH_OPENSSL
#endif

#include <list>

extern "C" {
#include <openabe/zml/zelement.h>
}

namespace oabe {

#if !defined(BP_WITH_OPENSSL)
void fp12_write_ostream(std::ostream& os, fp12_t a, int radix);
void fp6_write_ostream(std::ostream& os, fp6_t a, int radix);
void fp2_write_ostream(std::ostream& os, fp2_t a, int radix);
void fp_write_ostream(std::ostream& os, fp_t a, int radix);
void ep2_write_ostream(std::ostream &os, ep2_t p, int radix);
void ep_write_ostream(std::ostream &os, ep_t p, int radix);
#endif

#ifndef __ZPAIRING_H__
class OpenABEPairing;
#endif
// forward declaration
class OpenABEByteString;
class OpenABERNG;

#if !defined(BP_WITH_OPENSSL)
bool checkRelicError();
#endif

}

void ro_error(void);

void g1_map_op(const bp_group_t group, g1_ptr g, oabe::OpenABEByteString& msg);
const std::string g1_point_to_string(bp_group_t group, const g1_ptr p);
void g1_convert_to_bytestring(bp_group_t group, oabe::OpenABEByteString & s, const g1_ptr p);
void g1_convert_to_point(bp_group_t group, oabe::OpenABEByteString& s, g1_ptr p);

void g2_convert_to_point(bp_group_t group, oabe::OpenABEByteString& s, g2_ptr p);
const std::string g2_point_to_string(bp_group_t group, const g2_ptr p);
void g2_convert_to_bytestring(bp_group_t group, oabe::OpenABEByteString & s, g2_ptr p);

void gt_convert_to_point(bp_group_t group, oabe::OpenABEByteString& s, gt_ptr p);
void gt_convert_to_bytestring(bp_group_t group, oabe::OpenABEByteString& s, gt_ptr p, int should_compress);
const std::string gt_point_to_string(const bp_group_t group, gt_ptr p);

/// \class	ZP
/// \brief	Class for representing integer elements mod p.

namespace oabe {

// retrieve the group field of the BPGroup class
#define GET_BP_GROUP(g)    g->group

/// \class  ECGroup
/// \brief  Wrapper for managing elliptic curve groups
class BPGroup : public ZGroup {
public:
  bp_group_t   group;
  bignum_t     order;

  BPGroup(OpenABECurveID id);
  ~BPGroup();

  void getGroupOrder(bignum_t o);
};


/// \class  ZP
/// \brief  Class for ZP elements in ZML.
class ZP : public ZObject {
public:
  bignum_t m_ZP;
  bignum_t order;
  bool isInit, isOrderSet;
  ZP();
  ZP(uint32_t);
  ZP(char*, bignum_t);
  ZP(uint8_t*, uint32_t, bignum_t);
  ZP(bignum_t y);
  ZP(const ZP& w);

  ~ZP();
  ZP& operator+=(const ZP& x);
  ZP& operator*=(const ZP& x);
  ZP& operator=(const ZP& w);

  std::string getBytesAsString();
  OpenABEByteString getByteString() const;
  void getLengthAndByteString(OpenABEByteString &z) const;
  void setOrder(const bignum_t o);
  void setRandom(OpenABERNG *rng, bignum_t o);

  void setFrom(ZP&, uint32_t);
  bool ismember();
  void multInverse();

  friend ZP power(const ZP&, unsigned int);
  friend ZP power(const ZP&, const ZP&);
  friend ZP operator-(const ZP&);
  friend ZP operator-(const ZP&,const ZP&);
  friend ZP operator+(const ZP&,const ZP&);
  friend ZP operator*(const ZP&,const ZP&);
  friend ZP operator/(const ZP&,const ZP&);
  friend ZP operator<<(const ZP&, int);
  friend ZP operator>>(const ZP&, int);

  friend std::ostream& operator<<(std::ostream&, const ZP&);
  friend bool operator<(const ZP& x, const ZP& y);
  friend bool operator<=(const ZP& x, const ZP& y);
  friend bool operator>(const ZP& x, const ZP& y);
  friend bool operator>=(const ZP& x, const ZP& y);
  friend bool operator==(const ZP& x, const ZP& y);
  friend bool operator!=(const ZP& x, const ZP& y);

  ZP*    clone() const { return new ZP(*this); }
  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
  bool isEqual(ZObject*) const;
};

/// \class  G1
/// \brief  Class for G1 base field elements in ZML.
class G1 : public ZObject {
public:
  g1_ptr m_G1;
  bool isInit;
  std::shared_ptr<BPGroup> bgroup;

  G1(std::shared_ptr<BPGroup> bgroup);
  G1(const G1& w);
  ~G1();
  G1& operator*=(const G1& x);
  G1& operator=(const G1& w);

  void setRandom(OpenABERNG *rng);
  bool ismember(bignum_t);
  G1 exp(ZP);
  void multInverse();
  friend G1 operator-(const G1&);
  friend G1 operator/(const G1&,const G1&);
  friend G1 operator*(const G1&,const G1&);
  friend std::ostream& operator<<(std::ostream&, const G1&);
  friend bool operator==(const G1& x, const G1& y);
  friend bool operator!=(const G1& x,const G1& y);

  G1*    clone() const { return new G1(*this); }
  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
  bool isEqual(ZObject*) const;
};

/// \class  G2
/// \brief  Class for G2 field elements in ZML.
class G2 : public ZObject {
public:
  g2_ptr m_G2;
  bool isInit;
  std::shared_ptr<BPGroup> bgroup;

  G2(std::shared_ptr<BPGroup> bgroup);
  G2(const G2& w);
  ~G2();
  G2& operator*=(const G2& x);
  G2& operator=(const G2& w);

  void setRandom(OpenABERNG *rng);
  bool ismember(bignum_t);
  G2 exp(ZP);

  friend G2 operator-(const G2&);
  friend G2 operator/(const G2&,const G2&);
  friend G2 operator*(const G2&,const G2&);
  friend std::ostream& operator<<(std::ostream&, const G2&);
  friend bool operator==(const G2& x,const G2& y);
  friend bool operator!=(const G2& x,const G2& y);

  G2*    clone() const { return new G2(*this); }
  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
  bool isEqual(ZObject*) const;
};

/// \class  GT
/// \brief  Class for GT field elements in RELIC.
class GT : public ZObject {
public:
  gt_ptr m_GT;
  bool isInit;
  std::shared_ptr<BPGroup> bgroup;

  GT(std::shared_ptr<BPGroup> bgroup);
  GT(const GT& w);
  ~GT();
  GT& operator*=(const GT& x);
  GT& operator=(const GT& x);

  void enableCompression() { shouldCompress_ = true; };
  void disableCompression() { shouldCompress_ = false; };
  //void setRandom(OpenABERNG *rng);
  void setIdentity();
  bool isInfinity();
  bool ismember(bignum_t);
  GT exp(ZP);

  friend GT operator-(const GT&);
  friend GT operator/(const GT&,const GT&);
  friend GT operator*(const GT&,const GT&);
  friend std::ostream& operator<<(std::ostream& s, const GT&);
  friend bool operator==(const GT& x, const GT& y);
  friend bool operator!=(const GT& x, const GT& y);

  GT* clone() const { return new GT(*this); }
  void serialize(OpenABEByteString &result) const;
  void deserialize(OpenABEByteString &input);
  bool isEqual(ZObject*) const;

private:
  bool shouldCompress_;
};

/// \typedef    OpenABEElementList
/// \brief      Vector or list of elements
typedef std::vector<ZP> OpenABEElementList;

/// \typedef    OpenABEElementListIterator
/// \brief      Iterator for an OpenABEElementList of rows in an LSSS
typedef OpenABEElementList::iterator OpenABEElementListIterator;

}

// pairings definition
void multi_bp_map_op(const bp_group_t group, oabe::GT& gt,
                     std::vector<oabe::G1>& g1, std::vector<oabe::G2>& g2);

#endif	// __ZELEMENT_BP_H__
