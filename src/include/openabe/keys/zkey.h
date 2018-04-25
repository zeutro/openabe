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
///	\file   zkey.h
///
///	\brief  Abstract base class for key and parameter types.
///
///	\author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZKEY_H__
#define __ZKEY_H__

#include <map>

typedef enum OpenABEKeyType_ {
  OpenABEKEY_NONE,
  OpenABEKEY_SK_ENC,
  OpenABEKEY_PK_ENC,
  OpenABEKEY_CP_ENC,
  OpenABEKEY_KP_ENC,
  OpenABEKEY_MA_ENC,
  OpenABEKEY_PK_SIG,
} OpenABEKeyType;

/// \class	OpenABEKey
/// \brief	Abstract base class class for keys and parameters
namespace oabe {

class OpenABEKey : public OpenABEContainer {
protected:
  // 32-bytes for representing OpenABEKey Header information as follows:
  // 1 bytes for the library version
  uint8_t libraryVersion;
  // 1 byte for the curve identifier
  uint8_t curveID;
  // 1 byte for algorithm/scheme ID
  uint8_t algorithmID;
  // 32 bytes for UID
  OpenABEByteString uid;
  // remaining bytes for string ID
  std::string ID;
  // the key type ID
  OpenABEKeyType key_type;
  // key is a public or private key
  bool isPrivate;

public:
  OpenABEKey();
  OpenABEKey(const OpenABECurveID curveID, uint8_t algorithmID, const std::string ID, OpenABEByteString *uid = NULL);
  ~OpenABEKey();

  void    setAsPrivate() { isPrivate = true; }
  void    getHeader(OpenABEByteString &header);
  uint8_t getCurveID() { return this->curveID; }
  uint8_t getAlgorithmID() { return this->algorithmID; }
  uint8_t getLibID() { return this->libraryVersion; }
  OpenABEByteString& getUID() { return this->uid; }
  std::string getID() { return this->ID; }
  OpenABEKeyType getKeyType() { return this->key_type; }

  virtual OpenABE_ERROR exportKeyToBytes(OpenABEByteString &output);
  virtual OpenABE_ERROR loadKeyFromBytes(OpenABEByteString &input);

};

OpenABEKeyType OpenABE_KeyTypeFromAlgorithmID(uint8_t algorithmID);
const std::string OpenABE_KeyTypeToString(OpenABEKeyType key_type);
}

#endif	// __ZKEY_H__
