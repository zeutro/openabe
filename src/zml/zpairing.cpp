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
/// \file   zpairing.cpp
///
/// \brief  Implementation for bilinear maps (or pairings).
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __ZPAIRING_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>

extern "C" {
#include <openabe/zml/zelement.h>
}
using namespace std;

namespace oabe {

// Utility functions

/*!
 * Global pairing library initialization
 *
 * @return OpenABE_NOERROR or an error code
 */

OpenABE_ERROR
zMathInitLibrary()
{
  // Initialize ZML
  zml_init();
  return OpenABE_NOERROR;
}

/*!
 * Global pairing library shutdown
 *
 * @return OpenABE_NOERROR or an error code
 */

OpenABE_ERROR
zMathShutdownLibrary()
{
  // Cleanup ZML
  zml_clean();
  return OpenABE_NOERROR;
}

/*!
 * Factory for creating new OpenABEPairing objects
 *
 * @return The pairing object or NULL
 */

OpenABEPairing*
OpenABE_createNewPairing(const string &pairingParams)
{
  return new OpenABEPairing(pairingParams);
}

/*!
 * Convert a symmetric-equivalent security level into an ID string
 * for a set of pairing parameters.
 *
 * @return The corresponding ID string or NULL
 */

string
OpenABE_pairingParamsForSecurityLevel(OpenABESecurityLevel securityLevel)
{
  if(securityLevel == 128)
    return "BN_P256";
  return "";
}


/********************************************************************************
 * Implementation of the OpenABEPairing class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEPairing class.
 *
 */

OpenABEPairing::OpenABEPairing(const string &pairingParams) : ZObject()
{    
  AssertLibInit();
  // Look up the pairing parameters and set them
  this->curveID = getPairingCurveID(pairingParams);

  this->bpgroup  = make_shared<BPGroup>(this->curveID);
  zml_bignum_init(&this->order);
  this->bpgroup->getGroupOrder(this->order);
}

/*!
 * Constructor for the OpenABEPairing class.
 *
 */
OpenABEPairing::OpenABEPairing(const OpenABEPairing &copyFrom) : ZObject()
{
  AssertLibInit();
  // copy the pairing params first
  string pairingParams = copyFrom.getPairingParams();

  // Look up the pairing parameters and set them in RELIC
  this->curveID = getPairingCurveID(pairingParams);

  this->bpgroup  = make_shared<BPGroup>(this->curveID);
  zml_bignum_init(&this->order);
  this->bpgroup->getGroupOrder(this->order);
}

/*!
 * Destructor for the OpenABEPairing class.
 *
 */
OpenABEPairing::~OpenABEPairing()
{
  zml_bignum_free(order);
  this->bpgroup.reset();
}

void
OpenABEPairing::initZP(ZP& result, uint32_t v)
{
  result = v;
  result.setOrder(order);
}

ZP
OpenABEPairing::initZP()
{
  ZP z = (uint32_t) 0;
  z.setOrder(order);
  return z;
}

G1
OpenABEPairing::initG1()
{
  G1 g(this->bpgroup);
  return g;
}

G2
OpenABEPairing::initG2()
{
  G2 g(this->bpgroup);
  return g;
}

GT
OpenABEPairing::initGT()
{
  GT g(this->bpgroup);
  return g;
}

/*!
 * Generate and return a random group element in ZP.
 *
 * @return group element in ZP
 */
ZP
OpenABEPairing::randomZP(OpenABERNG *rng)
{
  ASSERT_NOTNULL(rng);
  ZP result;
  result.setRandom(rng, order);
  return result;
}

/*!
 * Generate and return a random group element in G1.
 *
 * @return group element in G1
 */
G1
OpenABEPairing::randomG1(OpenABERNG *rng)
{
	ASSERT_NOTNULL(rng);
	G1 result(this->bpgroup);
	result.setRandom(rng);
	return result;
}

/*!
 * Generate and return a random group element in G2.
 *
 * @return group element in G2
 */
G2
OpenABEPairing::randomG2(OpenABERNG *rng)
{
	ASSERT_NOTNULL(rng);
	G2 result(this->bpgroup);
	result.setRandom(rng);
	return result;
}

G1
OpenABEPairing::hashToG1(OpenABEByteString& keyPrefix, string msg)
{
  ASSERT_PAIRING(this);
  OpenABEByteString tmp;
  // set the key prefix
  tmp = keyPrefix;
  // append the message
  tmp += msg;
  // hash the message to G1
  // (note that g1_map first hashes to ZP, then to G1)
  G1 g1(this->bpgroup);
  std::string digest, str = tmp.toString();
  oabe::sha256(digest, str);
  uint8_t *xstr = (uint8_t *)digest.c_str();
  size_t xstr_len = digest.size();
  g1_map_op(GET_BP_GROUP(this->bpgroup), g1.m_G1, xstr, xstr_len);
  return g1;
}

GT
OpenABEPairing::pairing(G1& g1, G2& g2)
{
  GT result(this->bpgroup);
  bp_map_op(GET_BP_GROUP(this->bpgroup), result.m_GT, g1.m_G1, g2.m_G2);
  if(result.isInfinity()) {
    result.setIdentity();
  }
  return result;
}

void
OpenABEPairing::multi_pairing(GT& gt, std::vector<G1>& g1, std::vector<G2>& g2) {
  multi_bp_map_op(GET_BP_GROUP(this->bpgroup), gt, g1, g2);
  if(gt.isInfinity()) {
    gt.setIdentity();
  }
}

/*!
 * Return the pairing parameters string.
 *
 * @return Pairing parameters string
 */

string
OpenABEPairing::getPairingParams() const
{
  return this->pairingParams;
}

/*!
 * Return the pairing parameters ID.
 *
 * @return Pairing parameters ID
 */

OpenABECurveID
OpenABEPairing::getCurveID() const
{
  return this->curveID;
}

/*
 * Convert a pairing parameters identifier string into a RELIC
 * identifier for the parameters.
 *
 * @return An int representing the parameters, or -1 if not found.
 */

OpenABECurveID
getPairingCurveID(const string &paramsID)
{
  OpenABECurveID curveID = OpenABE_NONE_ID;

  if (paramsID == "BN_P254") {
    curveID = OpenABE_BN_P254_ID;
  } else if (paramsID == "BN_P256") {
    curveID = OpenABE_BN_P256_ID;
  } else if (paramsID == "BN_P382") {
    curveID = OpenABE_BN_P382_ID;
  } else {
    // Unrecognized parameter type
    throw OpenABE_ERROR_INVALID_PARAMS;
  }

  return curveID;
}

OpenABEByteString
OpenABEPairing::hashToBytes(uint8_t *buf, uint32_t buf_len)
{
  uint8_t hash[SHA256_LEN];
  sha256(hash, buf, buf_len);

  OpenABEByteString b;
  b.appendArray(hash, SHA256_LEN);
  return b;
}

// implements a variable-sized hash function
// block_len = len / md_len ... rounding up
// H(00 || hash_byte || m) || H(01 || hash_byte || m) || ... || H(n || hash_byte || m)
// ... where 'n' is block_len and 'm' is message
OpenABEByteString
OpenABEPairing::hashFromBytes(OpenABEByteString &buf, uint32_t target_len, uint8_t hash_prefix)
{
  // compute number of hash blocks needed
  int block_len = ceil(((double)target_len) / SHA256_LEN);
  // set the hash_len
  int hash_len = block_len * SHA256_LEN;
  uint8_t hash[hash_len+1];
  memset(hash, 0, hash_len+1);

  OpenABEByteString buf2 = buf;
  uint8_t count = 0;

  buf2.insertFirstByte(hash_prefix);
  buf2.insertFirstByte(count);
  uint8_t *ptr = buf2.getInternalPtr();
  uint8_t *hash_ptr = hash;

  for(int i = 0; i < block_len; i++) {
    // H(count || hash_prefix || buf)
    sha256(hash_ptr, buf2.getInternalPtr(), buf2.size());
    count++;
    ptr[0] = count;      // change block number
    hash_ptr += SHA256_LEN; // move ptr by SHA256_LEN size
  }

  OpenABEByteString b;
  b.appendArray(hash, target_len);
  return b;
}

}
