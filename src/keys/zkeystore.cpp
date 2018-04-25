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
/// \file   zkeystore.cpp
///
/// \brief  Class implementation for the OpenABE keystore and keystore manager.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OpenABEKEYSTORE_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <assert.h>
#include <openabe/openabe.h>

using namespace std;

namespace oabe {

/********************************************************************************
 * Implementation of the OpenABEKeystore class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEKeystore class.
 *
 */

OpenABEKeystore::OpenABEKeystore(): ZObject()
{
}

/*!
 * Destructor for the OpenABECiphertext class.
 *
 */

OpenABEKeystore::~OpenABEKeystore()
{
  std::map<std::string, shared_ptr<OpenABEKey>>::iterator iter;
  for (iter = this->pubKeys.begin(); iter != this->pubKeys.end(); ++iter) {
      // delete iter->second;
      shared_ptr<OpenABEKey> key = iter->second;
      if (key != nullptr) {
          key->zeroize(); // securely zeroize the keys
          key.reset(); // deletes the managed object
      }
  }
  this->pubKeys.clear();

  for (iter = this->secKeys.begin(); iter != this->secKeys.end(); ++iter) {
      // delete iter->second;
      shared_ptr<OpenABEKey> key = iter->second;
      if (key != nullptr) {
          key->zeroize(); // securely zeroize the keys
          key.reset(); // deletes the managed object
      }
  }
  this->secKeys.clear();
}

/*!
 * Insert a key into the keystore.
 *
 * @param Name of the key
 * @param Object containing the key
 */

OpenABE_ERROR
OpenABEKeystore::addKey(const string name, const shared_ptr<OpenABEKey>& component, zKeyType keyType)
{
    // Insert the key into the public or secret key maps
    if (keyType == KEY_TYPE_PUBLIC) {
        // Public key/parameter
        this->pubKeys[name] = component;
    } else if (keyType == KEY_TYPE_SECRET){
        // Secret key/parameter
        this->secKeys[name] = component;
    }
    return OpenABE_NOERROR;
}

/*!
 * Retrieve a key from the keystore
 * (searches for both public and secret)
 *
 * @param   Identifier of the key
 * @return  Object containing the key, or NULL if not found
 */

shared_ptr<OpenABEKey>
OpenABEKeystore::getKey(const string keyID) {
    shared_ptr<OpenABEKey> result = nullptr;

    // Look in the public keys list
    result = this->pubKeys[keyID];
    if (result != nullptr) {
        return result;
    }
    // Look in the secret keys list
    result = this->secKeys[keyID];
    if (result != nullptr) {
        return result;
    }
    // Did not find the selected key
    return nullptr;
}

/*!
 * Check whether an existing key has a specific
 * keyID in the keystore.
 *
 * @param Identifier of the key
 * @return true or false
 */
bool
OpenABEKeystore::checkSecretKey(const string keyID) {
    if(this->secKeys.count(keyID) != 0)
        return true;
    return false;
}


/*!
 * Retrieve a public key from the keystore.
 *
 * @param   Identifier of the key
 * @return  Object containing the key, or NULL if not found
 */

shared_ptr<OpenABEKey>
OpenABEKeystore::getPublicKey(const string keyID) {
    shared_ptr<OpenABEKey> result;

    // Look in the public keys list
    result = this->pubKeys[keyID];
    if (result != NULL) {
        return result;
    }
    // Did not find the selected key
    return nullptr;
}

/*!
 * Retrieve a secret key from the keystore.
 *
 * @param   Identifier of the key
 * @return  Object containing the key, or NULL if not found
 */

shared_ptr<OpenABEKey>
OpenABEKeystore::getSecretKey(const string keyID) {
    shared_ptr<OpenABEKey> result;

    // Look in the secret keys list
    result = this->secKeys[keyID];
    if (result != nullptr) {
        return result;
    }
    // Did not find the selected key
    return nullptr;
}

#if 0
/*!
 * Retrieve references to secret key in the keystore.
 *
 * @return  A vector of key references
 */

const vector<string>
OpenABEKeystore::getSecretKeyIDs() const {
    vector<string> keyRefs;

    std::map<std::string, shared_ptr<OpenABEKey>>::const_iterator iter;
    for (iter = this->secKeys.begin(); iter != this->secKeys.end(); ++iter) {
        keyRefs.push_back(iter->first);
    }
    // list will be empty if no secret keys in the keystore
    return keyRefs;
}
#endif


/*!
 * Delete a key from the keystore.
 *
 * @param[in] keyID     - Identifier of the key
 * @return              - An error code (OpenABE_ERROR_INVALID_KEY) or OpenABE_NOERROR
 */

OpenABE_ERROR
OpenABEKeystore::deleteKey(const string keyID) {
    // Find the key and destroy it
    shared_ptr<OpenABEKey> key = this->getKey(keyID);
    if (key != nullptr) {
        key->zeroize();
        bool foundInPubKey = false, foundInSecKey = false;
        // Remove key/value from our internal store via the iterator
        map<string, shared_ptr<OpenABEKey>>::iterator iter1 = this->pubKeys.find(keyID);
        map<string, shared_ptr<OpenABEKey>>::iterator iter2 = this->secKeys.find(keyID);

        if(iter1 != this->pubKeys.end()) {
            this->pubKeys.erase(iter1);
            foundInPubKey = true;
        }

        if(iter2 != this->secKeys.end()) {
            this->secKeys.erase(iter2);
            foundInSecKey = true;
        }

        // make sure key existed in one of two lists
        // otherwise return an invalid key error
        if(!foundInPubKey && !foundInSecKey) {
            return OpenABE_ERROR_INVALID_KEY;
        }
    }
    return OpenABE_NOERROR;
}

/*!
 * Verify that a given parameter ID is not already present in the keystore.
 *
 * @param[in] keyID     - Identifier of the key
 * @return              - true if the key is /not/ present
 */

bool
OpenABEKeystore::validateNewParamsID(const string &keyID) {
    return (this->getKey(keyID) == nullptr);
}


OpenABE_ERROR
OpenABEKeystore::exportKeyToBytes(const string keyID, OpenABEByteString &exportedKey) {
    shared_ptr<OpenABEKey> key = this->getKey(keyID);
    if (key == nullptr) {
        return OpenABE_ERROR_INVALID_INPUT;
    }

    exportedKey.clear();
    key->exportKeyToBytes(exportedKey);
    return OpenABE_NOERROR;
}

shared_ptr<OpenABEKey>
OpenABEKeystore::parseKeyHeader(const std::string keyID, OpenABEByteString &keyBlob, OpenABEByteString &outputKeyBytes) {
  shared_ptr<OpenABEKey> key = nullptr;

  // parse the result into a OpenABEKey structure
  // parses the header and the body from PKE keys
  key = this->constructKeyFromBytes(keyID, keyBlob, outputKeyBytes);
  if(key == nullptr) {
      THROW_ERROR(OpenABE_ERROR_INVALID_INPUT);
  }

  return key;
}


shared_ptr<OpenABEKey>
OpenABEKeystore::constructKeyFromBytes(const string &keyID, OpenABEByteString &keyBlob, OpenABEByteString &keyBytes) {
  size_t hdrLen = 3 + UID_LEN;
  shared_ptr<OpenABEKey> key = nullptr;

  try {
    if(keyBlob.size() < hdrLen) { THROW_ERROR(OpenABE_ERROR_INVALID_LENGTH); }
    OpenABEByteString keyHeader;
    size_t index = 0;
    // convert to OpenABEByteStrings
    keyHeader = keyBlob.unpack(&index);

    if(keyHeader.size() >= hdrLen) {
      // check that lib version correct
      ASSERT(keyHeader.at(0) <= OpenABE_LIBRARY_VERSION, OpenABE_ERROR_INVALID_LIBVERSION);

      OpenABECurveID curveID = OpenABE_getCurveID(keyHeader.at(1));
      uint8_t algID      = OpenABE_getSchemeID(keyHeader.at(2));
      OpenABEByteString uid  = keyHeader.getSubset(3, UID_LEN);
      OpenABEByteString id   = keyHeader.getSubset(hdrLen, keyHeader.size()-hdrLen);

      // alloc/construct the key
      key.reset(new OpenABEKey(curveID, algID, id.toString(), &uid));
      // return the serialized form of the key structure
      keyBytes.clear();
      keyBytes  = keyBlob.unpack(&index);
    }
    else {
      THROW_ERROR(OpenABE_ERROR_INVALID_KEY_HEADER);
    }
  } catch(OpenABE_ERROR &error) {
      cerr << "OpenABEKeystore::constructKeyFromBytes: " << OpenABE_errorToString(error) << endl;
  }
  return key;
}

}
