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
/// \file   zcontextske.cpp
///
/// \brief  Implementation for OpenABE context SKE and streaming SKE schemes.
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Utility functions for managing symmetric keys in a keystore
 ********************************************************************************/
namespace oabe {

/*!
 * Stores a symmetric key in a given Keystore.
 *
 * @param[in]   A Keystore reference.
 * @param[in]   A symmetric key identifier.
 * @param[in]	A reference to a OpenABESymKey object.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR OpenABE_storeSymmetricKey(OpenABEKeystore *gKeystore, const std::string keyID,
                                const shared_ptr<OpenABESymKey> &skey) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  try {
    // check input is valid
    ASSERT_NOTNULL(gKeystore);
    ASSERT_NOTNULL(skey);
    // add key into the keystore
    gKeystore->addKey(keyID, skey, KEY_TYPE_SECRET);
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

/*!
 * Load a symmetric key blob into a given Keystore.
 *
 * @param[in]   A Keystore reference.
 * @param[in]   A symmetric key identifier to store the key as.
 * @param[in]	A reference to a OpenABEByteString key blob.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR OpenABE_loadSymmetricKey(OpenABEKeystore *gKeystore, const std::string keyID,
                               OpenABEByteString *skeyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString keyBytes;
  shared_ptr<OpenABESymKey> symKey = nullptr;

  try {
    // check that input is valid
    ASSERT_NOTNULL(gKeystore);
    ASSERT_NOTNULL(skeyBlob);
    // construct symmetric key
    symKey.reset(new OpenABESymKey);
    symKey->loadKeyFromBytes(*skeyBlob);
    // add symmetric key into the keystore
    gKeystore->addKey(keyID, symKey, KEY_TYPE_SECRET);
    symKey.reset();
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

/*!
 * Retrieve a symmetric key from a given Keystore.
 *
 * @param[in]   A Keystore reference.
 * @param[in]   A symmetric key identifier.
 * @return  A reference to the requested OpenABESymKey or NULL if not found in the Keystore.
 */
shared_ptr<OpenABESymKey> OpenABE_getSymmetricKey(OpenABEKeystore *gKeystore,
                                          const std::string keyID) {
  shared_ptr<OpenABESymKey> skey = nullptr;

  // get the OpenABEKey stored inside the keystore
  shared_ptr<OpenABEKey> key = gKeystore->getSecretKey(keyID);
  if (key == nullptr) {
    return nullptr;
  }

  // convert the key into a OpenABESymKey structure
  skey = static_pointer_cast<OpenABESymKey>(key);
  if (skey == nullptr) {
    return nullptr;
  }

  return skey;
}

/*!
 * Delete a symmetric key from a given Keystore.
 *
 * @param[in]   A Keystore reference.
 * @param[in]   A symmetric key identifier.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR OpenABE_deleteSymmetricKey(OpenABEKeystore *gKeystore,
                                 const std::string keyID) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  try {
    // delete the key within the keystore
    if (gKeystore->deleteKey(keyID) != OpenABE_NOERROR) {
      throw OpenABE_ERROR_INVALID_INPUT;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

/*!
 * Export a OpenABEKey key in a given Keystore to a buffer.
 *
 * @param[in]   A Keystore reference.
 * @param[in]   A key identifier.
 * @param[out]	A reference to a OpenABEByteString output buffer.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR OpenABE_exportKey(OpenABEKeystore *gKeystore, const std::string keyID,
                        OpenABEByteString *outputKeyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  try {
    // check that input is valid
    ASSERT_NOTNULL(gKeystore);
    ASSERT_NOTNULL(outputKeyBlob);
    // retrieve the key from keystore using keyID
    if (gKeystore->exportKeyToBytes(keyID, *outputKeyBlob) != OpenABE_NOERROR) {
      throw OpenABE_ERROR_INVALID_KEY;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

/********************************************************************************
 * Implementation of the OpenABEContextSchemeStreamSKE class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEContextSchemeStreamSKE base class.
 *
 */
OpenABEContextSchemeStreamSKE::OpenABEContextSchemeStreamSKE() : ZObject() {
  this->m_AuthEncStream = nullptr;
  this->m_AuthDecStream = nullptr;
}

/*!
 * Destructor for the OpenABEContextSchemeSKE base class.
 *
 */
OpenABEContextSchemeStreamSKE::~OpenABEContextSchemeStreamSKE() {
  SAFE_DELETE(this->m_AuthEncStream);
  SAFE_DELETE(this->m_AuthDecStream);
}

OpenABE_ERROR OpenABEContextSchemeStreamSKE::keygen(const string &keyID) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABESymKey> skey = nullptr;

  try {
    // make sure secret key ID hasn't been used before
    bool does_exist = this->m_Keystore_.checkSecretKey(keyID);
    if (does_exist) {
      throw OpenABE_ERROR_IN_USE_ALREADY;
    }
    // select a new symmetric key for keyID
    skey.reset(new OpenABESymKey);
    skey->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES);
    // now we can add it to the keystore
    this->m_Keystore_.addKey(keyID, skey, KEY_TYPE_SECRET);
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABEContextSchemeStreamSKE::exportKey(const string &keyID,
                                               OpenABEByteString &keyBlob,
                                               const string password) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString tmpKeyBlob;

  try {
    // attempt to export the given keyID to the keyBlob output buffer
    if (OpenABE_exportKey(&this->m_Keystore_, keyID, &tmpKeyBlob) != OpenABE_NOERROR) {
      throw OpenABE_ERROR_INVALID_INPUT;
    }

    // check if user specified a password
    if (password != "") {
      // encrypt the exported key using the specified password
      if ((result = encryptUnderPassword(password, tmpKeyBlob, keyBlob)) !=
          OpenABE_NOERROR) {
        return result;
      }
    } else {
      // set the keyBlob
      keyBlob.clear();
      keyBlob += tmpKeyBlob;
    }
    // clear the temp buffer
    tmpKeyBlob.clear();
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR
OpenABEContextSchemeStreamSKE::loadPrivateKey(const string &keyID,
                                          OpenABEByteString &inputKeyBlob,
                                          const string password) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString keyBlob;

  try {
    // check if user specified a password
    if (password != "") {
      // decrypt inputKeyBlob into keyBlob using 'password'
      if ((result = decryptUnderPassword(password, inputKeyBlob, keyBlob)) !=
          OpenABE_NOERROR) {
        return result;
      }
    } else {
      keyBlob += inputKeyBlob;
    }

    // load the symmetric key without attempting to decrypt the blob first
    if ((result = OpenABE_loadSymmetricKey(&this->m_Keystore_, keyID, &keyBlob)) !=
        OpenABE_NOERROR) {
      return result;
    }

  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABEContextSchemeStreamSKE::deleteKey(const string &keyID) {
  return OpenABE_deleteSymmetricKey(&this->m_Keystore_, keyID);
}

OpenABE_ERROR OpenABEContextSchemeStreamSKE::encryptInit(const string &skID,
                                                 OpenABEByteString *iv) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABESymKey> symKey = nullptr;

  try {
    /* check if AuthEncStream has been allocated */
    if (this->m_AuthEncStream != nullptr) {
      SAFE_DELETE(this->m_AuthEncStream);
    }

    /* load OpenABESymKey using skID */
    symKey = OpenABE_getSymmetricKey(&this->m_Keystore_, skID);
    if (symKey == nullptr) {
      throw OpenABE_ERROR_INVALID_KEY;
    }
    /* now we can allocate the AuthEncStream class and set the symmetric key */
    this->m_AuthEncStream =
        new OpenABESymKeyAuthEncStream(DEFAULT_AES_SEC_LEVEL, symKey);
    /* perform encryptInit and verify there were no errors */
    result = this->m_AuthEncStream->encryptInit(iv);
    if (result != OpenABE_NOERROR) {
      throw result;
    }
    // check for the AAD
    if (this->aad.size() > 0) {
      /* set AAD accordingly */
      this->m_AuthEncStream->initAddAuthData(this->aad.getInternalPtr(),
                                             this->aad.size());
    } else {
      /* do the default here */
      this->m_AuthEncStream->initAddAuthData(NULL, 0);
    }
    result = this->m_AuthEncStream->setAddAuthData();
    ASSERT(result == OpenABE_NOERROR, result);

  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR
OpenABEContextSchemeStreamSKE::encryptUpdate(OpenABEByteString *plaintextBlock,
                                         OpenABEByteString *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    /* make sure we've called encryptInit already */
    ASSERT_NOTNULL(this->m_AuthEncStream);
    /* perform encryption update */
    this->m_AuthEncStream->encryptUpdate(plaintextBlock, ciphertext);

  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR
OpenABEContextSchemeStreamSKE::encryptFinalize(OpenABEByteString *ciphertext,
                                           OpenABEByteString *tag) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    /* make sure we've called encryptInit already */
    ASSERT_NOTNULL(this->m_AuthEncStream);
    /* finalize encryption */
    this->m_AuthEncStream->encryptFinalize(ciphertext, tag);
    /* delete AuthEncStream object */
    SAFE_DELETE(this->m_AuthEncStream);
    this->m_AuthEncStream = nullptr;

  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR
OpenABEContextSchemeStreamSKE::decryptInit(const string &skID, OpenABEByteString *iv,
                                       OpenABEByteString *tag) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABESymKey> symKey = nullptr;

  try {
    /* check if AuthEncStream has been allocated */
    if (this->m_AuthDecStream != nullptr) {
      SAFE_DELETE(this->m_AuthDecStream);
    }

    /* load OpenABESymKey using skID */
    symKey = OpenABE_getSymmetricKey(&this->m_Keystore_, skID);
    if (symKey == nullptr) {
      throw OpenABE_ERROR_INVALID_KEY;
    }

    /* now we can allocate the AuthEncStream class and set the symmetric key */
    this->m_AuthDecStream =
        new OpenABESymKeyAuthEncStream(DEFAULT_AES_SEC_LEVEL, symKey);
    /* perform decrypt init */
    this->m_AuthDecStream->decryptInit(iv, tag);
    // check for the AAD
    if (this->aad.size() > 0) {
      /* set AAD accordingly */
      this->m_AuthDecStream->initAddAuthData(this->aad.getInternalPtr(),
                                             this->aad.size());
    } else {
      /* do the default here */
      this->m_AuthDecStream->initAddAuthData(NULL, 0);
    }
    result = this->m_AuthDecStream->setAddAuthData();
    ASSERT(result == OpenABE_NOERROR, result);

  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR
OpenABEContextSchemeStreamSKE::decryptUpdate(OpenABEByteString *ciphertextBlock,
                                         OpenABEByteString *plaintext) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    /* make sure we've called encryptInit already */
    ASSERT_NOTNULL(this->m_AuthDecStream);
    /* perform encryption update */
    this->m_AuthDecStream->decryptUpdate(ciphertextBlock, plaintext);

  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR
OpenABEContextSchemeStreamSKE::decryptFinalize(OpenABEByteString *plaintext) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    /* make sure we've called encryptInit already */
    ASSERT_NOTNULL(this->m_AuthDecStream);
    /* perform encryption update */
    this->m_AuthDecStream->decryptFinalize(plaintext);

    SAFE_DELETE(this->m_AuthDecStream);
    this->m_AuthDecStream = nullptr;
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

}
