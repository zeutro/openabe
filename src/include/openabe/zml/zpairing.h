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
/// \file   zpairing.h
///
/// \brief  Class definition for bilinear maps (or pairings).
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZPAIRING_H__
#define __ZPAIRING_H__

/// \class	OpenABEPairing
/// \brief	Generic container for pairing functionality.
namespace oabe {

class OpenABEPairing : public ZObject {
public:
  OpenABEPairing(const std::string &pairingParams);
  OpenABEPairing(const OpenABEPairing &copyFrom);
  ~OpenABEPairing();
  void     initZP(ZP& z, uint32_t v);
  ZP       initZP();
  G1       initG1();
  G2       initG2();
  GT       initGT();

  ZP       randomZP(OpenABERNG *rng);
  G1       randomG1(OpenABERNG *rng);
  G2       randomG2(OpenABERNG *rng);

  OpenABEByteString hashToBytes(uint8_t*, uint32_t);
  OpenABEByteString hashFromBytes(OpenABEByteString &buf, uint32_t target_len, uint8_t hash_prefix);

  G1       hashToG1(OpenABEByteString&, std::string);
  GT       pairing(G1& g1, G2& g2);
  void     multi_pairing(GT& gt, std::vector<G1>& g1, std::vector<G2>& g2);

  std::string  getPairingParams() const;
  OpenABECurveID   getCurveID() const;
  std::shared_ptr<ZGroup> getGroup() { return this->bpgroup; }
  bignum_t     order;

protected:
  bool         isSymmetric;
  OpenABECurveID   curveID;
  std::string  pairingParams;
  std::shared_ptr<BPGroup>  bpgroup;
};

// Global library initialization and shutdown functions
OpenABE_ERROR zMathInitLibrary();
OpenABE_ERROR zMathShutdownLibrary();
// Convert a security level (in symmetric-equivalent bits) to pairing params
std::string OpenABE_pairingParamsForSecurityLevel(OpenABESecurityLevel securityLevel);
// Pairing creation functions
OpenABEPairing* OpenABE_createNewPairing(const std::string &pairingParams);
// Utility functions
OpenABECurveID  getPairingCurveID(const std::string &paramsID);

}

#endif	// __ZPAIRING_H__
