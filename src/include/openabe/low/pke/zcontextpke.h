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
/// \file   zcontextpke.h
///
/// \brief  Class definition for public-key encryption schemes.
///
/// \source One-pass DH KEM (in section 6.2.2.2 of NIST SP 800-56A)
///
/// \author J. Ayo Akinyele
///

#ifndef __ZCONTEXTPKE_H__
#define __ZCONTEXTPKE_H__

///
/// @class  OpenABEContextPKE
///
/// @brief  Abstract class for public-key encryption schemes.
///
namespace oabe {

class OpenABEContextPKE : public OpenABEContext {
public:
  // Constructors/destructors
  OpenABEContextPKE();
  ~OpenABEContextPKE();

  OpenABE_ERROR	initializeCurve(const std::string groupParams);
  OpenABE_ERROR generateParams(OpenABESecurityLevel securityLevel);
  virtual bool validatePublicKey(const std::shared_ptr<OpenABEKey>& key) = 0;
  virtual bool validatePrivateKey(const std::shared_ptr<OpenABEKey>& key) = 0;

  virtual OpenABE_ERROR generateParams(const std::string groupParams) = 0;

  virtual OpenABE_ERROR generateDecryptionKey(const std::string &keyID,
                                          const std::string &pkID,
                                          const std::string &skID) = 0;

  virtual OpenABE_ERROR encryptKEM(OpenABERNG *rng, const std::string &pkID,
                               OpenABEByteString *senderID, uint32_t keyBitLen,
                               const std::shared_ptr<OpenABESymKey>& key,
                               OpenABECiphertext *ciphertext) = 0;

  virtual OpenABE_ERROR decryptKEM(const std::string &pkID, const std::string &skID,
                               OpenABECiphertext *ciphertext, uint32_t keyBitLen,
                               const std::shared_ptr<OpenABESymKey>& key) = 0;
};

///
/// @class  OpenABEContextOPDH
///
/// @brief  Implementation derived from the One-Pass Diffie-Hellman Key Agreement scheme.
///			NIST SP 800-56A Recommendation for Pair-Wise Key Establishment Schemes Using
///			Discrete-Logarithm Cryptography: Section 6.2.2.2
///

class OpenABEContextOPDH : public OpenABEContextPKE {
public:
  // Constructors/destructors
  OpenABEContextOPDH(std::unique_ptr<OpenABERNG> rng);
  ~OpenABEContextOPDH();

  bool validatePublicKey(const std::shared_ptr<OpenABEKey>& key);
  bool validatePrivateKey(const std::shared_ptr<OpenABEKey>& key);

  OpenABE_ERROR generateParams(const std::string groupParams);
  OpenABE_ERROR generateDecryptionKey(const std::string &keyID,
                                  const std::string &pkID,
                                  const std::string &skID);

  OpenABE_ERROR encryptKEM(OpenABERNG *rng, const std::string &pkID,
                       OpenABEByteString *senderID, uint32_t keyBitLen,
                       const std::shared_ptr<OpenABESymKey>& key, OpenABECiphertext *ciphertext);

  OpenABE_ERROR decryptKEM(const std::string &pkID, const std::string &keyID,
                       OpenABECiphertext *ciphertext, uint32_t keyBitLen,
                       const std::shared_ptr<OpenABESymKey>& key);
};


///
/// @class  OpenABEContextSchemePKE
///
/// @brief  Abstract class for PKE schemes.
///

class OpenABEContextSchemePKE : public ZObject {
private:
  std::unique_ptr<OpenABEContextPKE>   m_KEM_;

public:
  OpenABEContextSchemePKE(std::unique_ptr<OpenABEContextPKE> kem);
  ~OpenABEContextSchemePKE();

  OpenABE_ERROR exportKey(const std::string &keyID, OpenABEByteString &keyBlob);
  OpenABE_ERROR	loadPublicKey(const std::string &keyID, OpenABEByteString &keyBlob);
  OpenABE_ERROR loadPrivateKey(const std::string &keyID, OpenABEByteString &keyBlob);
  OpenABE_ERROR deleteKey(const std::string &keyID);

  OpenABE_ERROR generateParams(const std::string groupParams);

  OpenABE_ERROR keygen(const std::string &keyID, const std::string &pkID, const std::string &skID);
  OpenABE_ERROR encrypt(OpenABERNG *rng, const std::string &pkID, const std::string &senderpkID,
                    const std::string& plaintext, OpenABECiphertext *ciphertext);
  OpenABE_ERROR decrypt(const std::string &pkID, const std::string &skID,
                    std::string &plaintext, OpenABECiphertext *ciphertext);
};

}

#endif // __ZCONTEXTPKE_H__
