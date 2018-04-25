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
/// \file   zcontextske.h
///
/// \brief  Class definition for OpenABE context symmetric-key encryption schemes.
///
/// \author J. Ayo Akinyele
///

#ifndef __ZCONTEXTSKE_H__
#define __ZCONTEXTSKE_H__

///
/// @class  OpenABEContextSchemeStreamSKE
///
/// @brief  Class for SKE schemes (authenticated encryption).
///
namespace oabe {

class OpenABEContextSchemeStreamSKE : public ZObject {
private:
  OpenABEByteString     aad;
  OpenABEKeystore m_Keystore_;
  OpenABESymKeyAuthEncStream *m_AuthEncStream;
  OpenABESymKeyAuthEncStream *m_AuthDecStream;

public:
  OpenABEContextSchemeStreamSKE();
  ~OpenABEContextSchemeStreamSKE();

  OpenABE_ERROR keygen(const std::string &keyID);
  OpenABE_ERROR exportKey(const std::string &keyID,
                      OpenABEByteString &keyBlob,
                      const std::string password);
  OpenABE_ERROR loadPrivateKey(const std::string &keyID,
                           OpenABEByteString &keyBlob,
                           const std::string password);
  OpenABE_ERROR deleteKey(const std::string &keyID);

  OpenABE_ERROR encryptInit(const std::string &skID, OpenABEByteString *iv);
  OpenABE_ERROR encryptUpdate(OpenABEByteString *plaintextBlock, OpenABEByteString *ciphertext);
  OpenABE_ERROR encryptFinalize(OpenABEByteString* ciphertext, OpenABEByteString *tag);

  OpenABE_ERROR decryptInit(const std::string &skID, OpenABEByteString *iv, OpenABEByteString *tag);
  OpenABE_ERROR decryptUpdate(OpenABEByteString *ciphertextBlock, OpenABEByteString *plaintext);
  OpenABE_ERROR decryptFinalize(OpenABEByteString *plaintext);
};


///
/// Utility functions -- managing symmetric keys in OpenABE
/// Note: this is independent of the keys managed and used in each scheme context
///

OpenABE_ERROR OpenABE_storeSymmetricKey(OpenABEKeystore *gKeystore,
                                const std::string keyID,
                                const std::shared_ptr<OpenABESymKey>& key);
OpenABE_ERROR OpenABE_exportKey(OpenABEKeystore *gKeystore,
                        const std::string keyID,
                        OpenABEByteString *outputKeyBlob);
OpenABE_ERROR OpenABE_loadSymmetricKey(OpenABEKeystore *gKeystore,
                               const std::string keyID,
                               OpenABEByteString *skeyBlob);
std::shared_ptr<OpenABESymKey> OpenABE_getSymmetricKey(OpenABEKeystore *gKeystore,
                                               const std::string keyID);
OpenABE_ERROR OpenABE_deleteSymmetricKey(OpenABEKeystore *gKeystore,
                                 const std::string keyID);

}

#endif // __ZCONTEXTSKE_H__
