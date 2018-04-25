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
///	\file   zcryptoutils.h
///
///	\brief  Miscellaneous cryptographic utilities.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZCRYPTOUTILS_H__
#define __ZCRYPTOUTILS_H__

namespace oabe {

/// @typedef    OpenABEHashFunctionType
///
/// @brief      Enumeration of supported hash function types

typedef enum _OpenABEHashFunctionType {
    HASH_FUNCTION_TYPE_SHA1 = 0,
    HASH_FUNCTION_TYPE_SHA256 = 1,
    HASH_FUNCTION_TYPE_SHA384 = 2,
    HASH_FUNCTION_TYPE_SHA512 = 3
} OpenABEHashFunctionType;

//
// Default hash function is SHA256, but this can be
// overridden from build options
//

#ifndef OpenABE_DEFAULT_HASH_FUNCTION_TYPE
#define OpenABE_DEFAULT_HASH_FUNCTION_TYPE  HASH_FUNCTION_TYPE_SHA256
#endif

// forward declare GT (for now)
class GT;
// hashing GT elements into a bytestring
bool  OpenABEUtilsHashToString(GT &input, uint32_t keyLen,
                           OpenABEByteString &result,
                           OpenABEHashFunctionType hashType = OpenABE_DEFAULT_HASH_FUNCTION_TYPE);
std::string OpenABEHashKey(const std::string attr_key);
// compute keyed hash
void OpenABEComputeHash(OpenABEByteString& key, OpenABEByteString& input, OpenABEByteString& output);
// generate a salted hash from the given password and store into the variable 'hash'
void generateHash(std::string& hash, const std::string& password);
// check password against a given 'salted hash'
bool checkPassword(const std::string& hash, const std::string& password);
// encrypt a given blob and password
OpenABE_ERROR encryptUnderPassword(const std::string password, OpenABEByteString &inputBlob, OpenABEByteString &encOutputBlob);
// decrypt a given blob using password
OpenABE_ERROR decryptUnderPassword(const std::string password, OpenABEByteString &inputCTBlob, OpenABEByteString &plainOutputBlob);

/*! \brief Calculates a SHA-256 hash
 *
 * @param[in] value The value to digest
 * @param[out] digest The digest
 * @throws zeutro::crypto::CryptoException value is empty or an
 *                                         internal error occured
 */
void sha256ToHex(std::string& hex_digest, const std::string& value);
void sha256(std::string &digest, uint8_t *val, size_t val_len);
void sha256(uint8_t *digest, uint8_t *val, size_t val_len);
void sha256(std::string& digest, const std::string& value);

}
#endif	// __ZCRYPTOUTILS_H__
