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
///	\file   zelliptic.h
///
///	\brief  Class definition files for ordinary elliptic curves.
///
///	\author J. Ayo Akinyele
///

#ifndef __ZELLIPTIC_H__
#define __ZELLIPTIC_H__

/// \class	OpenABEEllipticCurve
/// \brief	Generic container for NIST elliptic-curve functionality.
namespace oabe {

class OpenABEEllipticCurve : public ZObject {
public:
  OpenABEEllipticCurve(const std::string &ecParams);
  OpenABEEllipticCurve(const OpenABEEllipticCurve &copyFrom);
  ~OpenABEEllipticCurve();
  ZP_t initZP();
  ZP_t randomZP(OpenABERNG *rng);
  G_t  initG();
  // curve parameters
  G_t	getGenerator();
  void getGroupOrder(bignum_t o);
  ZP_t  getGroupOrder();

  std::string  getECParams() const;
  OpenABECurveID   getCurveID() const;
  bool         isAtInfinity(G_t& point);
  bool         isOnCurve(G_t& point);
  std::shared_ptr<ZGroup> getGroup() { return this->ecgroup; }

protected:
  OpenABECurveID	 curveID;
  std::shared_ptr<ECGroup>  ecgroup;
  std::string  ecParams;
};

// Convert a security level (in symmetric-equivalent bits) to pairing params
std::string OpenABE_ECParamsForSecurityLevel(OpenABESecurityLevel securityLevel);

// elliptic curve creation functions
OpenABEEllipticCurve* OpenABE_createNewEllipticCurve(const std::string &ecParams);

// Utility functions for curveIDs
std::string OpenABE_convertECCurveIDToString(uint8_t curveID);
OpenABECurveID  OpenABE_convertIntToCurveID(uint8_t curveID);
int OpenABE_convertStringToNID(std::string paramsID);
int OpenABE_convertCurveIDToNID(OpenABECurveID id);

}

#endif // __ZELLIPTIC_H__
