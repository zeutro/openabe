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
/// \file   zelliptic.cpp
///
/// \brief  Class implementation for ordinary elliptic curves (NIST).
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <memory>
#include <fstream>
#include <sstream>
#include <string>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Utilities for the OpenABEEllipticCurve
 ********************************************************************************/
namespace oabe {

/*!
 * Factory for creating new OpenABEEllipticCurve objects
 *
 * @return The pairing object or NULL
 */

OpenABEEllipticCurve *OpenABE_createNewEllipticCurve(const string &ecParams) {
  return new OpenABEEllipticCurve(ecParams);
}

string OpenABE_ECParamsForSecurityLevel(OpenABESecurityLevel securityLevel) {
  if (securityLevel == 128)
    return "NIST_P256";
  else if (securityLevel == 256)
    return "NIST_P384";
  else if (securityLevel == 512)
    return "NIST_P521";
  return "";
}

OpenABECurveID OpenABE_convertIntToCurveID(uint8_t curveID) {
  OpenABECurveID id;
  if (curveID == OpenABE_NIST_P256_ID) {
    id = OpenABE_NIST_P256_ID;
  } else if (curveID == OpenABE_NIST_P384_ID) {
    id = OpenABE_NIST_P384_ID;
  } else if (curveID == OpenABE_NIST_P521_ID) {
    id = OpenABE_NIST_P521_ID;
  } else {
    throw OpenABE_ERROR_INVALID_PARAMS_ID;
  }

  return id;
}

int OpenABE_convertStringToNID(string paramsID) {
  int NID = 0;
  if (paramsID == "NIST_P256") {
    NID = OBJ_sn2nid("prime256v1");
  } else if (paramsID == "NIST_P384") {
    NID = OBJ_sn2nid("secp384r1");
  } else if (paramsID == "NIST_P521") {
    NID = OBJ_sn2nid("secp521r1");
  } else if (paramsID == "BN_P254") {
#if defined(BP_WITH_OPENSSL)
    NID = NID_fp254bnb;
#else
    throw OpenABE_ERROR_INVALID_PARAMS_ID;
#endif
  } else {
    // Unrecognized parameter type
    throw OpenABE_ERROR_INVALID_PARAMS_ID;
  }

  return NID;
}

int OpenABE_convertCurveIDToNID(OpenABECurveID id) {
  int NID = 0;
  if (id == OpenABE_NIST_P256_ID) {
    NID = OBJ_sn2nid("prime256v1");
  } else if (id == OpenABE_NIST_P384_ID) {
    NID = OBJ_sn2nid("secp384r1");
  } else if (id == OpenABE_NIST_P521_ID) {
    NID = OBJ_sn2nid("secp521r1");
  } else if (id == OpenABE_BN_P254_ID) {
#if defined(BP_WITH_OPENSSL)
    NID = NID_fp254bnb;
#else
    throw OpenABE_ERROR_INVALID_PARAMS_ID;
#endif
  } else {
    /* NOTE: add other curves as they are added to openssl for BP */
    // Unrecognized parameter type
    throw OpenABE_ERROR_INVALID_PARAMS_ID;
  }

  return NID;
}


/********************************************************************************
 * Implementation of the OpenABEEllipticCurve class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEEllipticCurve base class.
 *
 */
OpenABEEllipticCurve::OpenABEEllipticCurve(const string &ecParams) : ZObject() {
  AssertLibInit();
  // Look up the EC parameters (throws an error if not valid)
  OpenABECurveID id = OpenABE_convertStringToCurveID(ecParams);
  this->ecParams = ecParams;
  this->curveID = id;
  this->ecgroup = make_shared<ECGroup>(id);
}

/*!
 * Constructor for the OpenABEEllipticCurve class.
 *
 */

OpenABEEllipticCurve::OpenABEEllipticCurve(const OpenABEEllipticCurve &copyFrom)
    : ZObject() {
  AssertLibInit();
  this->ecParams = copyFrom.getECParams();

  // Look up the EC parameters (throws an error if not valid)
  OpenABECurveID id = OpenABE_convertStringToCurveID(this->ecParams);
  this->curveID = id;
  this->ecgroup = make_shared<ECGroup>(id);
}

/*!
 * Destructor for the OpenABEContextABE base class.
 *
 */
OpenABEEllipticCurve::~OpenABEEllipticCurve() {}

/*!
 * Return the elliptic curve parameter string.
 *
 * @return Curve parameter string
 */

string OpenABEEllipticCurve::getECParams() const { return this->ecParams; }

/*!
 * Return the elliptic curve parameter ID.
 *
 * @return Curve parameter ID
 */

OpenABECurveID OpenABEEllipticCurve::getCurveID() const { return this->curveID; }

ZP_t
OpenABEEllipticCurve::initZP()
{
    ZP_t z;
    this->getGroupOrder(z.order);
    z.isOrderSet = true;
    return z;
}

/*!
 * Generate and return a random group element in ZP.
 *
 * @return group element in ZP
 */
ZP_t OpenABEEllipticCurve::randomZP(OpenABERNG *rng) {
  ZP_t result;
  this->getGroupOrder(result.order);
  result.isOrderSet = true;
  result.setRandom(rng);
  return result;
}

G_t
OpenABEEllipticCurve::initG()
{
    G_t g(this->ecgroup);
    return g;
}

/*!
 * Return a generator G of the selected elliptic curve.
 *
 * @return group element in G
 */
G_t OpenABEEllipticCurve::getGenerator() {
  G_t result(this->ecgroup);
  this->ecgroup->getGenerator(result.m_G);
  return result;
}

/*!
 * Return the order of the selected elliptic curve.
 *
 * @return order of the group in ZP.
 */
ZP_t OpenABEEllipticCurve::getGroupOrder() {
  ZP_t result;
  this->ecgroup->getGroupOrder(result.m_ZP);
  return result;
}

void OpenABEEllipticCurve::getGroupOrder(bignum_t o) {
  ASSERT_NOTNULL(o);
  this->ecgroup->getGroupOrder(o);
}

/*!
 * Test whether a point is at infinity on the elliptic curve.
 *
 * @return Success or failure.
 */
bool OpenABEEllipticCurve::isAtInfinity(G_t &point) {
  if (ec_point_is_inf(GET_GROUP(this->ecgroup), point.m_G) == 1) {
    return true;
  }
  return false;
}

/*!
 * Test whether a point is on the elliptic curve.
 *
 * @return Success or failure.
 */
bool OpenABEEllipticCurve::isOnCurve(G_t &point) {
  if (ec_point_is_on_curve(GET_GROUP(this->ecgroup), point.m_G)) {
    return true;
  }

  return false;
}

/*!
 * Convert a uint8_t into an elliptic curve identifier.
 *
 * @return a string of the elliptic curve ID.
 */
string OpenABE_convertECCurveIDToString(uint8_t curveID) {
  if (curveID == OpenABE_NIST_P256_ID) {
    return "NIST_P256";
  } else if (curveID == OpenABE_NIST_P384_ID) {
    return "NIST_P384";
  } else if (curveID == OpenABE_NIST_P521_ID) {
    return "NIST_P521";
  } else {
    return "";
  }
}

}
