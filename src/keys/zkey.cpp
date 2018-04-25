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
/// \file   zkey.cpp
///
/// \brief  Class implementation for storing/managing all types of OpenABE keys.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __ZKEY_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEKey class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEKey class.
 *
 */

OpenABEKey::OpenABEKey() : OpenABEContainer() {
  this->curveID = OpenABE_NONE_ID;
  this->algorithmID = OpenABE_SCHEME_NONE;
  this->libraryVersion = OpenABE_LIBRARY_VERSION;
  this->ID = "";
  this->key_type = OpenABEKEY_NONE;
  this->isPrivate = false;
}

/*!
 * Constructor for the OpenABEKey class.
 *
 */

OpenABEKey::OpenABEKey(const OpenABECurveID curveID, uint8_t algorithmID, const string ID,
               OpenABEByteString *uid)
    : OpenABEContainer() {
  // store the curve identifier
  this->curveID = curveID;
  // the identifier of the scheme in OpenABE
  this->algorithmID = algorithmID;
  // current library version
  this->libraryVersion = OpenABE_LIBRARY_VERSION;
  if (uid != NULL && uid->size() == UID_LEN) {
    // random identifier that is public but useful for deriving keys
    this->uid = *uid;
  } else {
    // if 'uid' input is NULL, then just generate an id internally
    OpenABERNG rng;
    rng.getRandomBytes(&this->uid, UID_LEN);
  }
  // can be any string to represent the key holder's identification
  this->ID = ID;
  this->key_type = OpenABE_KeyTypeFromAlgorithmID(algorithmID);
  this->isPrivate = false;
}

/*!
 * Destructor for the OpenABEKey class.
 *
 */

OpenABEKey::~OpenABEKey() {}

/*!
 * Obtain the serialized form of the OpenABEKey header.
 *
 */

void OpenABEKey::getHeader(OpenABEByteString &header) {
  header.clear();
  header.push_back(this->libraryVersion);
  header.push_back(this->curveID);
  header.push_back(this->algorithmID);
  header += this->uid;
  header += this->ID;
  return;
}

OpenABE_ERROR
OpenABEKey::exportKeyToBytes(OpenABEByteString &output) {
  output.clear();
  OpenABEByteString keyHeader, keyBytes;
  // libVersion || curveID || AlgID || uid || id
  this->getHeader(keyHeader);
  // serialize the key structure
  this->serialize(keyBytes);
  // first pack the key header
  // then pack the key bytes
  output.pack(keyHeader.getInternalPtr(), keyHeader.size());
  output.pack(keyBytes.getInternalPtr(), keyBytes.size());
  // clear the contents of the intermediate buffers
  keyHeader.clear();
  keyBytes.clear();

  return OpenABE_NOERROR;
}

OpenABE_ERROR
OpenABEKey::loadKeyFromBytes(OpenABEByteString &input) {
  this->deserialize(input);
  return OpenABE_NOERROR;
}

OpenABEKeyType OpenABE_KeyTypeFromAlgorithmID(uint8_t algorithmID) {
  if (algorithmID == OpenABE_SCHEME_PK_OPDH)
    return OpenABEKEY_PK_ENC;
  else if (algorithmID == OpenABE_SCHEME_CP_WATERS ||
           algorithmID == OpenABE_SCHEME_CP_WATERS_CCA)
    return OpenABEKEY_CP_ENC;
  else if (algorithmID == OpenABE_SCHEME_KP_GPSW ||
           algorithmID == OpenABE_SCHEME_KP_GPSW_CCA)
    return OpenABEKEY_KP_ENC;
  else if (algorithmID == OpenABE_SCHEME_PKSIG_ECDSA)
    return OpenABEKEY_PK_SIG;
  else
    return OpenABEKEY_NONE;
}

const std::string OpenABE_KeyTypeToString(OpenABEKeyType key_type) {
  if (key_type == OpenABEKEY_SK_ENC)
    return "SymKey";
  else if (key_type == OpenABEKEY_PK_ENC)
    return "PubKey";
  else if (key_type == OpenABEKEY_CP_ENC)
    return "CP-ABEKey";
  else if (key_type == OpenABEKEY_KP_ENC)
    return "KP-ABEKey";
  else if (key_type == OpenABEKEY_PK_SIG)
    return "PKSigKey";

  return "Invalid KeyType";
}
}
