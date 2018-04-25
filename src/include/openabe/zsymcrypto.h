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
///	\file   zsymcrypto.h
///
///	\brief  Class definition for PKE and ABE thin context wrappers
///
///	\author Alan Dunn and J. Ayo Akinyele
///

#ifndef __ZSYMCRYPTO__
#define __ZSYMCRYPTO__

#include <memory>
#include <string>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openabe/zobject.h>
#include <openabe/utils/zerror.h>
#include <openabe/utils/zbytestring.h>
#include <openabe/utils/zconstants.h>
#include <openabe/utils/zexception.h>
#include <openabe/tools/zprng.h>

namespace oabe {

namespace crypto {

///
/// @class  OpenABESymKeyAuthEnc
///
/// @brief  Class for performing authenticated symmetric encryption using AES in GCM mode
///

class OpenABESymKeyAuthEnc : ZObject {
private:
  EVP_CIPHER *cipher;
  uint8_t iv[AES_BLOCK_SIZE+1];
  OpenABEByteString aad;
  OpenABEByteString key;
  bool aad_set;
  uint32_t iv_len;

public:
  OpenABESymKeyAuthEnc(int securitylevel, const std::string& zkey);
  OpenABESymKeyAuthEnc(int securitylevel, OpenABEByteString& zkey);
  ~OpenABESymKeyAuthEnc();

  void chooseRandomIV();
  void setAddAuthData(OpenABEByteString &aad);
  void setAddAuthData(uint8_t* aad, uint32_t aad_len);
  OpenABE_ERROR encrypt(const std::string& plaintext, OpenABEByteString* iv,
                    OpenABEByteString* ciphertext, OpenABEByteString* tag);
  bool decrypt(std::string& plaintext, OpenABEByteString* iv,
               OpenABEByteString* ciphertext, OpenABEByteString* tag);
};

class OpenABESymKeyHandle {
public:
  virtual void encrypt(std::string& ciphertext,
                       const std::string& plaintext) = 0;
  virtual void decrypt(std::string& plaintext,
                       const std::string& ciphertext) = 0;
  virtual void exportRawKey(std::string& key) = 0;
  virtual void exportKey(std::string& key) = 0;
};

// Implementation of SymmetricKeyHandle
class OpenABESymKeyHandleImpl : public OpenABESymKeyHandle {
public:
  void encrypt(std::string& ciphertext,
               const std::string& plaintext);
  void decrypt(std::string& plaintext,
               const std::string& ciphertext);
  void exportRawKey(std::string& key);
  void exportKey(std::string& key);

  OpenABESymKeyHandleImpl(const std::string& keyBytes,
                      bool apply_b64_encode = false);
  OpenABESymKeyHandleImpl(OpenABEByteString& keyBytes,
                      OpenABEByteString& authData,
                      bool apply_b64_encode = false);
  virtual ~OpenABESymKeyHandleImpl();

protected:
  int security_level_;
  std::string key_;
  bool b64_encode_;
  OpenABEByteString authData_;
};

// Hash-based key derivation function
void OpenABEComputeHKDF(OpenABEByteString& key, OpenABEByteString& salt,
    		            OpenABEByteString& info, size_t key_len,
    		            OpenABEByteString& output_key);
// generate a random symmetric key
void generateSymmetricKey(std::string& key, uint32_t keyLen);
const std::string printAsHex(const std::string& bin_buf);

}

}

#endif // __ZSYMCRYPTO__
