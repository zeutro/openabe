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
/// \file   zkeystore.h
///
/// \brief  Class definition for the OpenABE keystore.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZKEYSTORE_H__
#define __ZKEYSTORE_H__

#include <map>
#include <vector>

namespace oabe {

// Data structures

typedef enum _zKeyType {
  KEY_TYPE_PUBLIC,
  KEY_TYPE_SECRET
} zKeyType;

/// \class  ZKeystore
/// \brief  Keystore class for the OpenABE. Stores public and secret parameters
///         and keys, each indexed by a string identifier.
//
class OpenABEKeystore : public ZObject {
public:
  OpenABEKeystore();
  ~OpenABEKeystore();

  OpenABE_ERROR addKey(const std::string name,
                       const std::shared_ptr<OpenABEKey>& component,
                       zKeyType keyType);
  std::shared_ptr<OpenABEKey> getPublicKey(const std::string keyID);
  std::shared_ptr<OpenABEKey> getSecretKey(const std::string keyID);
  std::shared_ptr<OpenABEKey> getKey(const std::string keyID);

  bool checkSecretKey(const std::string keyID);
  OpenABE_ERROR deleteKey(const std::string keyID);

  bool validateNewParamsID(const std::string &keyID);
  // search/extract key references
#if 0
  const std::vector<std::string> getSecretKeyIDs() const;
#endif
  // import/export routines
  std::shared_ptr<OpenABEKey> parseKeyHeader(const std::string keyID,
                                          OpenABEByteString &keyBlob,
                                          OpenABEByteString &outputKeyBytes);
  std::shared_ptr<OpenABEKey> constructKeyFromBytes(const std::string &keyID,
                                                OpenABEByteString &keyBlob,
                                                OpenABEByteString &keyBytes);
  OpenABE_ERROR exportKeyToBytes(const std::string keyID, OpenABEByteString &exportedKey);

protected:
  std::map<std::string, std::shared_ptr<OpenABEKey>> pubKeys;
  std::map<std::string, std::shared_ptr<OpenABEKey>> secKeys;
};

typedef std::pair<std::string,int> KeyRef;

}

#endif	// __ZKEYSTORE_H__
