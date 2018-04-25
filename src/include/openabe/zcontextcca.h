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
/// \file   zcontextcca.h
///
/// \brief  Base class implementation for OpenABE context CCA schemes
///
/// \author J. Ayo Akinyele
///

#ifndef __ZCONTEXTCCA_H__
#define __ZCONTEXTCCA_H__

///
/// @class  OpenABEContextCCA
///
/// @brief  Abstract class for ABE KEM context (CCA security).
///
namespace oabe {

class OpenABEContextCCA : public OpenABEContextABE {
protected:
  std::unique_ptr<OpenABEContextSchemeCPA> abeSchemeContext;

public:
  // Constructors/destructors
  OpenABEContextCCA(std::unique_ptr<OpenABEContextSchemeCPA> scheme_);
  ~OpenABEContextCCA();
  void        setSchemeType(OpenABE_SCHEME scheme_type) { this->abeSchemeContext->setSchemeType(scheme_type); }
  OpenABE_SCHEME  getSchemeType() { return this->abeSchemeContext->getSchemeType(); }

//  virtual OpenABE_ERROR   generateParams(OpenABESecurityLevel securityLevel,
//                                     const std::string &mpkID, const std::string &mskID) = 0;
  virtual OpenABE_ERROR   generateParams(const std::string groupParams,
                                     const std::string &mpkID, const std::string &mskID) = 0;

  // Methods iff KEM is MA-ABE
  OpenABE_ERROR   generateGlobalParams(const std::string groupParams, const std::string &gpkID);
  OpenABE_ERROR   generateAuthorityParams(const std::string &gpkID, const std::string &auth_mpkID, const std::string &auth_mskID);

  // export and import methods
  OpenABEByteString* getHashKey(const std::string &mpkID);
  OpenABE_ERROR   exportKey(const std::string &keyID, OpenABEByteString &keyBlob);
  OpenABE_ERROR   loadMasterPublicParams(const std::string &mpkID, OpenABEByteString &mpkBlob);
  OpenABE_ERROR   loadMasterSecretParams(const std::string &mskID, OpenABEByteString &mskBlob);
  OpenABE_ERROR   loadUserSecretParams(const std::string &skID, OpenABEByteString &skBlob);
  OpenABE_ERROR   deleteKey(const std::string keyID);
  bool        checkSecretKey(const std::string keyID);
};

///
/// @class  OpenABEContextGenericCCA
///
/// @brief  A generic transformation that converts a CPA-secure ABE scheme
///         into one that is CCA-secure.
///

class OpenABEContextGenericCCA : public OpenABEContextCCA {
public:
  // Constructors/destructors
  OpenABEContextGenericCCA(std::unique_ptr<OpenABEContextSchemeCPA> scheme);
  ~OpenABEContextGenericCCA();

//  OpenABE_ERROR   generateParams(OpenABESecurityLevel securityLevel,
//                             const std::string &mpkID, const std::string &mskID);
  OpenABE_ERROR   generateParams(const std::string groupParams,
                             const std::string &mpkID, const std::string &mskID);
  OpenABE_ERROR   generateDecryptionKey(OpenABEFunctionInput *keyInput, const std::string &keyID,
                                    const std::string &mpkID, const std::string &mskID,
                                    const std::string &gpkID="", const std::string &GID="");
  OpenABE_ERROR   encryptKEM(OpenABERNG *rng, const std::string &mpkID, const OpenABEFunctionInput *encryptInput,
                         uint32_t keyByteLen, const std::shared_ptr<OpenABESymKey>& key, OpenABECiphertext *ciphertext);
  OpenABE_ERROR   decryptKEM(const std::string &mpkID, const std::string &keyID,
                         OpenABECiphertext *ciphertext, uint32_t keyByteLen, const std::shared_ptr<OpenABESymKey>& key);
};


///
/// @class  OpenABEContextSchemeCCA
///
/// @brief  ABE scheme context for CCA security.
///

class OpenABEContextSchemeCCA : public ZObject {
protected:
  std::unique_ptr<OpenABEContextCCA>	m_KEM_;

public:
  OpenABEContextSchemeCCA(std::unique_ptr<OpenABEContextCCA> kem_);
  ~OpenABEContextSchemeCCA();

  OpenABEKeystore *getKeystore() const { return this->m_KEM_->getKeystore(); }
  OpenABE_SCHEME  getSchemeType() const { return this->m_KEM_->getSchemeType(); }

  OpenABE_ERROR   exportKey(const std::string &keyID, OpenABEByteString &keyBlob);
  OpenABE_ERROR   loadMasterPublicParams(const std::string &mpkID, OpenABEByteString &mpkBlob);
  OpenABE_ERROR   loadMasterSecretParams(const std::string &mskID, OpenABEByteString &mskBlob);
  OpenABE_ERROR   loadUserSecretParams(const std::string &skID, OpenABEByteString &skBlob);
  OpenABE_ERROR   deleteKey(const std::string keyID);
  bool        checkSecretKey(const std::string keyID);

//  OpenABE_ERROR   generateParams(OpenABESecurityLevel securityLevel,
//                                     const std::string &mpkID, const std::string &mskID);
  OpenABE_ERROR   generateParams(const std::string groupParams,
                                     const std::string &mpkID, const std::string &mskID);
  // Methods iff KEM is MA-ABE
  OpenABE_ERROR   generateGlobalParams(const std::string groupParams, const std::string &gpkID);
  OpenABE_ERROR   generateAuthorityParams(const std::string &gpkID, const std::string &auth_mpkID,
                                      const std::string &auth_mskID);

  OpenABE_ERROR   keygen(OpenABEFunctionInput *keyInput, const std::string &keyID, const std::string &mpkID,
                                            const std::string &mskID, const std::string &gpkID="",
                                            const std::string &GID="");
  OpenABE_ERROR   encrypt(const std::string& mpkID, const OpenABEFunctionInput *encryptInput,
                      const std::string& plaintext, OpenABECiphertext *ciphertext1, OpenABECiphertext *ciphertext2);
  OpenABE_ERROR   decrypt(const std::string &mpkID, const std::string &keyID, std::string& plaintext,
                      OpenABECiphertext *ciphertext1, OpenABECiphertext *ciphertext2);
};

///
/// @class  OpenABEContextSchemeCCAWithATZN
///
/// @brief  ABE scheme context for CCA security (for amortized ABE).
///

class OpenABEContextSchemeCCAWithATZN : public ZObject {
protected:
  std::unique_ptr<OpenABEContextCCA>	m_KEM_;

public:
  OpenABEContextSchemeCCAWithATZN(std::unique_ptr<OpenABEContextCCA> kem_);
  ~OpenABEContextSchemeCCAWithATZN();

  OpenABEKeystore *getKeystore() const { return this->m_KEM_->getKeystore(); }
  OpenABE_SCHEME  getSchemeType() const { return this->m_KEM_->getSchemeType(); }

  OpenABE_ERROR   exportKey(const std::string &keyID, OpenABEByteString &keyBlob);
  OpenABE_ERROR   loadMasterPublicParams(const std::string &mpkID, OpenABEByteString &mpkBlob);
  OpenABE_ERROR   loadMasterSecretParams(const std::string &mskID, OpenABEByteString &mskBlob);
  OpenABE_ERROR   loadUserSecretParams(const std::string &skID, OpenABEByteString &skBlob);
  OpenABE_ERROR   deleteKey(const std::string keyID);
  bool        checkSecretKey(const std::string keyID);

//  OpenABE_ERROR   generateParams(OpenABESecurityLevel securityLevel,
//                             const std::string &mpkID,
//                             const std::string &mskID);
  OpenABE_ERROR   generateParams(const std::string groupParams,
                             const std::string &mpkID,
                             const std::string &mskID);
  // Methods iff KEM is MA-ABE
  OpenABE_ERROR   generateGlobalParams(const std::string groupParams, const std::string &gpkID);
  OpenABE_ERROR   generateAuthorityParams(const std::string &gpkID,
                                      const std::string &auth_mpkID,
                                      const std::string &auth_mskID);

  OpenABE_ERROR   keygen(OpenABEFunctionInput *keyInput, const std::string &keyID, const std::string &mpkID,
                     const std::string &mskID, const std::string &gpkID="", const std::string &GID="");
  std::unique_ptr<oabe::crypto::OpenABESymKeyHandle> encrypt(const std::string& mpkID,
                                                        const OpenABEFunctionInput *encryptInput,
                                                        OpenABECiphertext *ciphertext);
  std::unique_ptr<oabe::crypto::OpenABESymKeyHandle> decrypt(const std::string &mpkID,
                                                        const std::string &keyID,
                                                        OpenABECiphertext *ciphertext);
};


}

#endif /* ifdef __ZCONTEXTCCA_H__ */
