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
/// \file   zcontextabe.h
///
/// \brief  Base class definition for OpenABE context ABE schemes
///
/// \author J. Ayo Akinyele
///

#ifndef __ZCONTEXTABE_H__
#define __ZCONTEXTABE_H__

///
/// @class  OpenABEContextABE
///
/// @brief  Abstract class for ABE-KEM scheme.
///
namespace oabe {

class OpenABEContextABE : public OpenABEContext {
public:
  // Constructors/destructors
  OpenABEContextABE();
  ~OpenABEContextABE();

  OpenABE_ERROR	initializeCurve(const std::string groupParams);
  void        setSchemeType(OpenABE_SCHEME scheme_type) { this->algID = scheme_type; }
  OpenABE_SCHEME  getSchemeType() { return this->algID; }
//  virtual OpenABE_ERROR generateParams(OpenABESecurityLevel securityLevel,
//                                   const std::string &mpkID, const std::string &mskID) = 0;
  virtual OpenABE_ERROR generateParams(const std::string groupParams,
                                   const std::string &mpkID, const std::string &mskID) = 0;
  virtual OpenABE_ERROR generateDecryptionKey(OpenABEFunctionInput *keyInput, const std::string &keyID,
                                          const std::string &mpkID, const std::string &mskID,
                                          const std::string &gpkID="", const std::string &GID="") = 0;
  virtual OpenABE_ERROR encryptKEM(OpenABERNG *rng, const std::string &mpkID, const OpenABEFunctionInput *encryptInput,
                               uint32_t keyByteLen, const std::shared_ptr<OpenABESymKey>& key,
                               OpenABECiphertext *ciphertext) = 0;
  virtual OpenABE_ERROR decryptKEM(const std::string &mpkID, const std::string &keyID, OpenABECiphertext *ciphertext,
                               uint32_t keyByteLen, const std::shared_ptr<OpenABESymKey>& key) = 0;
};


///
/// @class  OpenABEContextScheme
///
/// @brief  ABE scheme context for CPA security.
///         Specifically, provides support for CP-, KP- and MA-ABE schemes
///

class OpenABEContextSchemeCPA : public ZObject {
private:
  OpenABE_ERROR    loadKey(const std::string &ID, OpenABEByteString &keyBlob, zKeyType keyType);
  bool         isMAABE;

protected:
  std::unique_ptr<OpenABEContextABE>	m_KEM_;

public:
  OpenABEContextSchemeCPA(std::unique_ptr<OpenABEContextABE> kem_);
  ~OpenABEContextSchemeCPA();

  void setSchemeType(OpenABE_SCHEME scheme_type) { this->m_KEM_->setSchemeType(scheme_type); }
  OpenABE_SCHEME getSchemeType() { return this->m_KEM_->getSchemeType(); }

  OpenABEByteString* getHashKey(const std::string &mpkID);
  OpenABE_ERROR exportKey(const std::string &keyID, OpenABEByteString &keyBlob);
  OpenABE_ERROR loadMasterPublicParams(const std::string &mpkID, OpenABEByteString &mpkBlob);
  OpenABE_ERROR loadMasterSecretParams(const std::string &mskID, OpenABEByteString &mskBlob);
  OpenABE_ERROR loadUserSecretParams(const std::string &skID, OpenABEByteString &skBlob);
  OpenABE_ERROR deleteKey(const std::string keyID);
  bool checkSecretKey(const std::string keyID);

  OpenABE_ERROR generateParams(OpenABESecurityLevel securityLevel,
                                     const std::string &mpkID, const std::string &mskID);
  OpenABE_ERROR generateParams(const std::string groupParams,
                                     const std::string &mpkID, const std::string &mskID);
  // Methods iff KEM is MA-ABE
  OpenABE_ERROR generateGlobalParams(const std::string groupParams, const std::string &gpkID);
  OpenABE_ERROR generateAuthorityParams(const std::string &gpkID, const std::string &auth_mpkID, const std::string &auth_mskID);

  OpenABE_ERROR keygen(OpenABEFunctionInput *keyInput, const std::string &keyID, const std::string &mpkID,
                   const std::string &mskID, const std::string &gpkID="", const std::string &GID="");
  OpenABE_ERROR encrypt(OpenABERNG *rng, const std::string &mpkID, const OpenABEFunctionInput *encryptInput,
                    OpenABEByteString *plaintext, OpenABECiphertext *ciphertext);
  OpenABE_ERROR decrypt(const std::string &mpkID, const std::string &keyID,
                    OpenABEByteString *plaintext, OpenABECiphertext *ciphertext);
};

}

#endif /* ifdef __ZCONTEXTABE_H__ */
