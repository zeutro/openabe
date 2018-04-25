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
/// \file   zcontextpksig.h
///
/// \brief  Class definition for OpenABE context PKSIG schemes.
///
/// \author J. Ayo Akinyele
///

#ifndef __ZCONTEXTPKSIG_H__
#define __ZCONTEXTPKSIG_H__

#include <memory>

namespace oabe {

class OpenABEContextPKSIG : public OpenABEContext {
protected:
  EC_GROUP *group;
  bool validateParams(const std::string &paramsID) { return true; };
  bool validatePkey(EVP_PKEY* pkey, bool expectPrivate);

public:
  // Constructors/destructors
  OpenABEContextPKSIG();
  ~OpenABEContextPKSIG();

  OpenABE_ERROR	initializeCurve(const std::string groupParams);
  bool validatePublicKey(const std::shared_ptr<OpenABEPKey>& key);
  bool validatePrivateKey(const std::shared_ptr<OpenABEPKey>& key);

  OpenABE_ERROR generateParams(const std::string groupParams);
  OpenABE_ERROR keygen(const std::string &pkID, const std::string &skID);
  OpenABE_ERROR sign(OpenABEPKey *privKey, OpenABEByteString *message, OpenABEByteString *signature);
  OpenABE_ERROR verify(OpenABEPKey *pubKey, OpenABEByteString *message, OpenABEByteString *signature);
};


///
/// @class  OpenABEContextSchemePKSIG
///
/// @brief  Abstract scheme context for PKSIG.
///

class OpenABEContextSchemePKSIG : ZObject {
private:
  std::unique_ptr<OpenABEContextPKSIG>	m_PKSIG;

public:
  OpenABEContextSchemePKSIG(std::unique_ptr<OpenABEContextPKSIG> pksig);
  ~OpenABEContextSchemePKSIG();

  OpenABE_ERROR exportKey(const std::string &keyID, OpenABEByteString &keyBlob);
  OpenABE_ERROR	loadPublicKey(const std::string &keyID, OpenABEByteString &keyBlob);
  OpenABE_ERROR loadPrivateKey(const std::string &keyID, OpenABEByteString &keyBlob);
  OpenABE_ERROR	deleteKey(const std::string &keyID);

  OpenABE_ERROR generateParams(const std::string groupParams);
  OpenABE_ERROR keygen(const std::string &pkID, const std::string &skID);
  OpenABE_ERROR sign(const std::string &skID, OpenABEByteString *message, OpenABEByteString *signature);
  OpenABE_ERROR verify(const std::string &pkID, OpenABEByteString *message, OpenABEByteString *signature);
};

}

#endif // __ZCONTEXTPKSIG_H__

