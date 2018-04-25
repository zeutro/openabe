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
/// \file   zcryptoutils.cpp
///
/// \brief  Miscellaneous cryptographic utilities.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OpenABECRYPTOUTILS_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace std;

/********************************************************************************
 * Global utility routines
 ********************************************************************************/
namespace oabe {

/*!
 * Utility for hashing a group element into a string.
 *
 */

bool OpenABEUtilsHashToString(GT &input, uint32_t keyLen, OpenABEByteString &result,
                          OpenABEHashFunctionType hashType) {
  stringstream concatResult;
  OpenABEByteString serializedResult;
  uint32_t numBytes = 0;

  result.clear();
  input.disableCompression();
  input.serialize(serializedResult);
  input.enableCompression();

  for (uint32_t i = 0; numBytes < keyLen; i++, numBytes += SHA256_LEN) {
    concatResult.clear();
    concatResult << numBytes << serializedResult << serializedResult.size();
    std::string hash;
    sha256(hash, (uint8_t *)(concatResult.str().c_str()),
           concatResult.str().size());
    result.appendArray((uint8_t *)hash.c_str(), SHA256_LEN);
  }

  return true;
}

string OpenABEHashKey(const string attr_key) {
  OpenABEByteString hex_digest;
  string hash;
  if (attr_key.size() > 16) {
	sha256(hash, (uint8_t *)(attr_key.c_str()), attr_key.size());
	hex_digest += hash.substr(0,8);
	return hex_digest.toLowerHex();
  }
  return attr_key;
}

void OpenABEComputeHash(OpenABEByteString& key, OpenABEByteString& input, OpenABEByteString& output) {
  string digest, error_msg = "";
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
  const EVP_MD *md = EVP_sha256();
  size_t digest_size;

  if (input.size() == 0) {
	error_msg = "No bytes to digest";
	goto out;
  }

  if (!md_ctx) {
	error_msg = "EVP_MD_CTX_create";
	goto out;
  }

  if (!EVP_DigestInit(md_ctx, md)) {
	error_msg = "EVP_DigestInit";
	goto out;
  }

  // load the key
  if (!EVP_DigestUpdate(md_ctx, key.getInternalPtr(), key.size())) {
	error_msg = "EVP_DigestUpdate: load the key";
	goto out;
  }
  // load the data
  if (!EVP_DigestUpdate(md_ctx, input.getInternalPtr(), input.size())) {
	error_msg = "EVP_DigestUpdate: load the input";
	goto out;
  }

  digest_size = EVP_MD_size(md);
  // Just to be safe, check digest_size before resizing the output
  if (digest_size > EVP_MAX_MD_SIZE) {
	error_msg = "EVP_MD_size";
	goto out;
  }
  digest.resize(EVP_MD_size(md));

  if (!EVP_DigestFinal_ex(md_ctx, (unsigned char *)&digest[0], nullptr)) {
	error_msg = "EVP_DigestFinal_ex";
	goto out;
  }
  output = digest;
out:
  if (md_ctx) {
    EVP_MD_CTX_destroy(md_ctx);
  }
  if (error_msg != "") {
   throw CryptoException(error_msg);
  }
}

/*!
 * Generate a salted hash from a given password and encode the resulting
 * salt and hash back to user.
 *
 * @param[out] hash      - empty string variable to store the generated salt and computed hash.
 * @param[in]  password  - a password or passphrase to generate a hash against.
 * @return
 */
void generateHash(std::string &hash, const std::string &password) {
  OpenABERNG rng;
  OpenABEByteString pword, salt, result, genHash;
  ASSERT(password.size() > 0, OpenABE_ERROR_INVALID_INPUT);
  /* set the password */
  pword = password;
  /* generate a salt */
  rng.getRandomBytes(&salt, SALT_LEN);
  /* produce a hash using the default iteration count */
  genHash = OpenABEPBKDF(pword, HASH_LEN, salt);
  /* return hash = salt + outputHash */
  result = salt + genHash;
  hash = result.toLowerHex();
  /* clear buffers */
  pword.clear();
  salt.clear();
  genHash.clear();
}

/*!
 * Check password against a given salted hash.
 *
 * @param[in] hash      - a generated hash.
 * @param[in] password  - a password or passphrase to check against the hash.
 * @return true or false
 */
bool checkPassword(const std::string &hash, const std::string &password) {
  OpenABEByteString result, pword, outputHash;
  bool answer;
  ASSERT(hash.size() > 0, OpenABE_ERROR_INVALID_INPUT);
  /* convert hex string into a binary buffer */
  ASSERT(result.fromHex(hash), OpenABE_ERROR_INVALID_INPUT);
  ASSERT(result.size() == (SALT_LEN + HASH_LEN), OpenABE_ERROR_INVALID_INPUT);

  /* split the input into salt and hash */
  OpenABEByteString salt = result.getSubset(0, SALT_LEN);
  OpenABEByteString inputHash =
      result.getSubset(SALT_LEN, result.size() - SALT_LEN);

  /* check the password with the recovered salt */
  pword = password;
  outputHash = OpenABEPBKDF(pword, HASH_LEN, salt);
  /*  check if output hash is equivalent to input hash
      -- if so, return true...otherwise, false */
  if (inputHash == outputHash)
    answer = true;
  else
    answer = false;
  /* cleanup */
  pword.clear();
  salt.clear();
  outputHash.clear();
  return answer;
}

OpenABE_ERROR encryptUnderPassword(const std::string password,
                               OpenABEByteString &inputBlob,
                               OpenABEByteString &encOutputBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString pword, salt, key, output, iv, ct, tag;
  string inBlob, key_str;
  unique_ptr<oabe::crypto::OpenABESymKeyAuthEnc> authEnc = nullptr;
  OpenABERNG rng;

  try {
    inBlob = inputBlob.toString();
    // convert the 'password' into a key + generate a salt.
    pword = password;
    // generate salt
    rng.getRandomBytes(&salt, SALT_LEN);
    // derive the key using PBKDF2 under generated salt
    key = OpenABEPBKDF(pword, DEFAULT_SYM_KEY_BYTES, salt);
    // use derived key to encrypt input blob
    authEnc.reset(
        new oabe::crypto::OpenABESymKeyAuthEnc(DEFAULT_AES_SEC_LEVEL, key));
    // encrypt the input blob
    authEnc->encrypt(inBlob, &iv, &ct, &tag);
    output.smartPack(iv);
    output.smartPack(ct);
    output.smartPack(tag);
    // concatenate bytes into caller's encOutputBlob object
    encOutputBlob += salt;
    encOutputBlob += output;
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  key.zeroize();
  salt.zeroize();
  return result;
}

OpenABE_ERROR decryptUnderPassword(const string password,
                               OpenABEByteString &inputCTBlob,
                               OpenABEByteString &plainOutputBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString pwd, ctBlob, salt, key;
  OpenABEByteString iv, ct, tag;
  unique_ptr<oabe::crypto::OpenABESymKeyAuthEnc> authEnc = nullptr;
  string ptBlob;

  try {
    // validate the input lengths
    ASSERT(inputCTBlob.size() > SALT_LEN, OpenABE_ERROR_INVALID_INPUT);
    // first recover the salt
    salt = inputCTBlob.getSubset(0, SALT_LEN);
    // then recover the ciphertext
    ctBlob = inputCTBlob.getSubset(SALT_LEN, inputCTBlob.size() - SALT_LEN);
    // now parse sym ciphertext
    size_t index = 0;
    iv = ctBlob.smartUnpack(&index);
    ct = ctBlob.smartUnpack(&index);
    tag = ctBlob.smartUnpack(&index);
    // convert the 'password' into a key + generate a salt.
    pwd = password;
    // derive the key (with default number of iterations)
    key = OpenABEPBKDF(pwd, DEFAULT_SYM_KEY_BYTES, salt);
    // use key to decrypt CT
    authEnc.reset(
        new oabe::crypto::OpenABESymKeyAuthEnc(DEFAULT_AES_SEC_LEVEL, key));
    if (!authEnc->decrypt(ptBlob, &iv, &ct, &tag)) {
      ptBlob.clear();
      throw OpenABE_ERROR_DECRYPTION_FAILED;
    }
    plainOutputBlob = ptBlob;
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  key.zeroize();
  salt.zeroize();
  return result;
}

void sha256(uint8_t *digest, uint8_t *val, size_t val_len) {
  std::string d;
  const std::string value = std::string((const char *)val, val_len);
  sha256(d, value);
  memcpy(digest, (uint8_t *)d.c_str(), SHA256_LEN);
}

void sha256(string &digest, uint8_t *val, size_t val_len) {
  const string value = string((const char *)val, val_len);
  sha256(digest, value);
}

void sha256(string &digest, const string &value) {
  string error_msg = "";
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
  const EVP_MD *md = EVP_sha256();
  size_t digest_size;

  if (value.size() == 0) {
    error_msg = "No bytes to digest";
    goto out;
  }

  if (!md_ctx) {
    error_msg = "EVP_MD_CTX_create";
    goto out;
  }

  if (!EVP_DigestInit(md_ctx, md)) {
    error_msg = "EVP_DigestInit";
    goto out;
  }

  if (!EVP_DigestUpdate(md_ctx, value.data(), value.size())) {
    error_msg = "EVP_DigestUpdate";
    goto out;
  }

  digest_size = EVP_MD_size(md);
  // Just to be safe, check digest_size before resizing the output
  if (digest_size > EVP_MAX_MD_SIZE) {
    error_msg = "EVP_MD_size";
    goto out;
  }
  digest.resize(EVP_MD_size(md));

  if (!EVP_DigestFinal_ex(md_ctx, (unsigned char *)&digest[0], nullptr)) {
    error_msg = "EVP_DigestFinal_ex";
    goto out;
  }

out:
  if (md_ctx) {
    EVP_MD_CTX_destroy(md_ctx);
  }
  if (error_msg != "") {
    throw CryptoException(error_msg);
  }
}

void sha256ToHex(std::string &hex_digest, const std::string &value) {
  OpenABEByteString tmp;
  string bin_digest;
  sha256(bin_digest, value);
  tmp = bin_digest;
  hex_digest = tmp.toLowerHex();
}
}
