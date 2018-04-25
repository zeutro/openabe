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
///	\file   zkdf.h
///
///	\brief  Key derivation function.
///
///	\author J. Ayo Akinyele
///

#ifndef __ZKDF_H__
#define __ZKDF_H__

#undef HMAC
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

///
/// @class  OpenABEKDF
///
/// @brief  Class for a Key Derivation Function
///         Approved Alternative 1: NIST SP 800-56A (Section 5.8.1)
///
namespace oabe {

class OpenABEKDF : public ZObject {
private:
	uint8_t  hashPrefix;
	uint32_t hashLen;
	uint32_t maxInputLen;

public:
  OpenABEKDF(uint8_t hashPrefix = KDF_HASH_FUNCTION_PREFIX,
         uint32_t hashLen = SHA2_BITLEN,
         uint32_t maxInputLen = OpenABE_MAX_KDF_BITLENGTH);
  ~OpenABEKDF();

  OpenABEByteString DeriveKey(OpenABEByteString &Z, uint32_t keyBitLen, OpenABEByteString &metadata);
};

///
/// @brief  OpenABEPBKDF wrapper for Password-based Key Derivation Function
///         (As described in RFC 2898)
OpenABEByteString OpenABEPBKDF(OpenABEByteString &password, uint32_t keydataLenBytes,
                       OpenABEByteString &salt, int iterationCount = OpenABE_KDF_ITERATION_COUNT);

}

#endif // __ZKDF_H__
