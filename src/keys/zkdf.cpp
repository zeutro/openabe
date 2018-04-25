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
/// \file   zkdf.cpp
///
/// \brief  Implementation for key derivation functions.
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEKDF class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEKDF class.
 *
 */

OpenABEKDF::OpenABEKDF(uint8_t hashPrefix, uint32_t hashLen, uint32_t maxInputLen)
    : ZObject() {
  // select a hash prefix for KDFs
  this->hashPrefix = hashPrefix;
  // bitlength of target hash function, H
  this->hashLen = hashLen;
  // max bitlength of input to hash function
  this->maxInputLen = maxInputLen;
}

/*!
 * Destructor for the OpenABEKDF class.
 *
 */

OpenABEKDF::~OpenABEKDF() {}

/*!
 * A concatenated KDF from NIST SP800-56A - Section 5.8.1 for deriving keys.
 * Returns the derived key of size keydataLenBytes.
 *
 * @param[in]   the shared key represented as a bytestring.
 * @param[in]   the number of bits for the returned key.
 * @param[in]   auxiliary information that is provided as input into the KDF.
 * @return  A OpenABEByteString object that contains the derived key.
 */

OpenABEByteString OpenABEKDF::DeriveKey(OpenABEByteString &Z, uint32_t keyBitLen,
                                OpenABEByteString &metadata) {
  // compute number of hash blocks needed (round up)
  OpenABEByteString buffer;
  uint32_t count = 1;

  // ceiling of keydataLen / hashLen (bitwise)
  size_t reps_len = (size_t)ceil(((double)keyBitLen) / this->hashLen);
  if (reps_len > OpenABE_MAX_KDF_BITLENGTH) {
    throw OpenABE_ERROR_INVALID_LENGTH;
  }

  // buffer = counter || hashPrefix || Z || Metadata
  buffer.setFirstBytes(count);
  buffer.push_back(this->hashPrefix);
  buffer.appendArray(Z.getInternalPtr(), Z.size());
  buffer.appendArray(metadata.getInternalPtr(), metadata.size());

  if (buffer.size() > this->maxInputLen) {
    throw OpenABE_ERROR_INVALID_LENGTH;
  }

  // set the hash_len
  int hash_len = reps_len * this->hashLen;
  uint8_t hash[hash_len + 1];
  memset(hash, 0, hash_len + 1);

  uint8_t *hash_ptr = hash;
  for (size_t i = 0; i < reps_len; i++) {
    // H(count++ || prefix || Z || Metadata)
    sha256(hash_ptr, buffer.getInternalPtr(), buffer.size());
    count++;
    buffer.setFirstBytes(count);
    hash_ptr += this->hashLen; // move ptr by hashLen bytes
  }

  uint32_t keydataBytes = keyBitLen / 8;
  OpenABEByteString keyMaterial;
  keyMaterial.appendArray(hash, keydataBytes);
  return keyMaterial;
}


/********************************************************************************
 * Implementation of the OpenABEPBKDF wrapper
 ********************************************************************************/

int PKCS5_PBKDF2_HMAC_SHA256(const char *pass, int passlen,
                             const unsigned char *salt, int saltlen, int iter,
                             int keylen, unsigned char *out) {
  return PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, EVP_sha256(),
                           keylen, out);
}

/*!
 * Applies PBKDF2 to a password and salt for a specified number of iterations.
 * Returns the derived key of size keydataLenBytes.
 *
 * @param[in]   a password.
 * @param[in]   the number of bytes for the returned key.
 * @param[in]   a salt for the given password.
 * @param[in]  iteration count (DEFAULT = 10000).
 * @return  A OpenABEByteString object that contains the derived key.
 */

OpenABEByteString OpenABEPBKDF(OpenABEByteString &password, uint32_t keydataLenBytes,
                       OpenABEByteString &salt, int iterationCount) {
  ASSERT(password.size() > 0, OpenABE_ERROR_INVALID_INPUT);
  ASSERT(salt.size() > 0, OpenABE_ERROR_INVALID_INPUT);
  ASSERT(keydataLenBytes > 0, OpenABE_ERROR_INVALID_INPUT);

  /* cheap allocation for keydataLenBytes */
  OpenABEByteString outputHash;
  outputHash.fillBuffer(0, keydataLenBytes);
  /* call PBKDF2 function in OpenSSL */
  PKCS5_PBKDF2_HMAC_SHA256((const char *)password.getInternalPtr(),
                           password.size(), salt.getInternalPtr(), salt.size(),
                           iterationCount, (int)keydataLenBytes,
                           outputHash.getInternalPtr());

  return outputHash;
}
}
