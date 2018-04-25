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
/// \file   zcontextabe.cpp
///
/// \brief  Abstract base class for the OpenABE context ABE
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

#include <openabe/openabe.h>

/********************************************************************************
 * Implementation of the OpenABEContextABE class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEContextABE base class.
 *
 */
OpenABEContextABE::OpenABEContextABE() : OpenABEContext() {}

/*!
 * Destructor for the OpenABEContextABE base class.
 *
 */
OpenABEContextABE::~OpenABEContextABE() {}

/*!
 * Initialize the pairing structure in underlying pairing library
 *
 * @param   String for initializing the group parameters
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextABE::initializeCurve(const string groupParams) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  if (this->m_Pairing_ != nullptr) {
    return result;
  }
  // Instantiate a OpenABE pairing object with the given parameters
  this->m_Pairing_.reset(OpenABE_createNewPairing(groupParams));
  if (this->m_Pairing_ == nullptr) {
    throw OpenABE_ERROR_INVALID_GROUP_PARAMS;
  }
  return result;
}


/********************************************************************************
 * Implementation of the OpenABEContextSchemeCPA class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEContextSchemeCPA base class.
 * Note: we add to
 */
OpenABEContextSchemeCPA::OpenABEContextSchemeCPA(unique_ptr<OpenABEContextABE> kem_) : ZObject() {
  ASSERT_NOTNULL(kem_.get());
  if (kem_->getSchemeType() == OpenABE_SCHEME_KP_GPSW ||
             kem_->getSchemeType() == OpenABE_SCHEME_CP_WATERS) {
    this->isMAABE = false;
  } else {
    /* unrecognized scheme type */
    throw OpenABE_ERROR_INVALID_INPUT;
  }
  this->m_KEM_ = move(kem_);
}

/*!
 * Destructor for the OpenABEContextABE base class.
 *
 */
OpenABEContextSchemeCPA::~OpenABEContextSchemeCPA() {}

/*!
 * Generate parameters of the pairing curve based on a string identifier.
 *
 * @param[in]   specific string identifier to instantiate the pairing curve.
 * @param[in]   a string identifier for the master public parameters.
 * @param[in]   a string identifier for the master secret parameters.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCPA::generateParams(const string groupParams, const string &mpkID,
                                 const string &mskID) {
  return this->m_KEM_->generateParams(groupParams, mpkID, mskID);
}

OpenABE_ERROR
OpenABEContextSchemeCPA::generateGlobalParams(const string groupParams,
                                       const string &gpkID) {
  return OpenABE_ERROR_NOT_IMPLEMENTED;
}

OpenABE_ERROR
OpenABEContextSchemeCPA::generateAuthorityParams(const string &gpkID,
                                          const string &auth_mpkID,
                                          const string &auth_mskID) {
  return OpenABE_ERROR_NOT_IMPLEMENTED;
}

/*!
 * Retrieve the hash function key from the master public parameters
 *
 * @param[in]   identifier for the MPK in the keystore.
 * @param[out]  a pointer to the internal OpenABEByteString of the hash key
 * @return      OpenABEByteString of hash key (should not be freed by caller)
 */
OpenABEByteString*
OpenABEContextSchemeCPA::getHashKey(const std::string &mpkID) {
	std::shared_ptr<OpenABEKey> MPK = this->m_KEM_->getKeystore()->getPublicKey(mpkID);
	if (!MPK) {
	    throw OpenABE_ERROR_INVALID_PARAMS;
	} else {
		// hash key defined for every scheme in the OpenABE
		return MPK->getByteString("k");
	}
}


/*!
 * Export a key from the keystore given the key identifier.
 *
 * @param[in]   identifier for the key.
 * @param[out]  an allocated OpenABEByteString to store the exported key header/body.
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCPA::exportKey(const string &keyID, OpenABEByteString &keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString tmpKeyBlob;

  try {
    // attempt to export the given keyID to a temp keyBlob output buffer
    if (OpenABE_exportKey(this->m_KEM_->getKeystore(), keyID, &tmpKeyBlob) !=
        OpenABE_NOERROR) {
      throw OpenABE_ERROR_INVALID_INPUT;
    }

    // just set the keyBlob
    keyBlob.clear();
    keyBlob += tmpKeyBlob;
    // clear the temp buffer
    tmpKeyBlob.clear();
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

/*!
 * Generic method for loading a key header/body regardless of the key type.
 *
 * @param[in]	identifier for the key.
 * @param[in]	serialized blob that represents the key parameters.
 * @param[in]	an optional password to derive a key for decrypting the serialized blob.
 * @param[in]   a key type for designating storage in keystore.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCPA::loadKey(const string &ID, OpenABEByteString &keyBlob,
                          zKeyType keyType) {
  OpenABEByteString outputKeyBytes;
  shared_ptr<OpenABEKey> KEY = this->m_KEM_->getKeystore()->parseKeyHeader(
      ID, keyBlob, outputKeyBytes);
  if (KEY == nullptr) {
    return OpenABE_ERROR_INVALID_INPUT;
  }

  // initialize the pairing object if not already
  if (this->m_KEM_->getPairing() == nullptr) {
    this->m_KEM_->initializeCurve(
        OpenABE_convertCurveIDToString((OpenABECurveID)KEY->getCurveID()));
  }

  // validate the header is not malformed
  if (KEY->getCurveID() != this->m_KEM_->getPairing()->getCurveID() ||
      KEY->getAlgorithmID() != this->m_KEM_->getAlgorithmID()) {
    // SAFE_DELETE(KEY);
    return OpenABE_ERROR_INVALID_KEY_HEADER;
  }
  // now, we can load the key
  KEY->setGroup(this->m_KEM_->getPairing()->getGroup());
  KEY->loadKeyFromBytes(outputKeyBytes);
  this->m_KEM_->getKeystore()->addKey(ID, KEY, keyType);

  return OpenABE_NOERROR;
}

/*!
 * Load and validate the master public parameters.
 *
 * @param[in]	identifier for the public key in the keystore.
 * @param[in]	serialized blob that represents the public parameters.
 * @param[in]	an optional password to derive a key for decrypting the serialized blob.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCPA::loadMasterPublicParams(const string &mpkID,
                                         OpenABEByteString &mpkBlob) {
  return this->loadKey(mpkID, mpkBlob, KEY_TYPE_PUBLIC);
}

/*!
 * Load and validate the master secret parameters.
 *
 * @param[in]	identifier for the secret key in the keystore.
 * @param[in]	serialized blob that represents the secret parameters.
 * @param[in]	an optional password to derive a key for decrypting the serialized blob.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCPA::loadMasterSecretParams(const string &mskID,
                                         OpenABEByteString &mskBlob) {
  return this->loadKey(mskID, mskBlob, KEY_TYPE_SECRET);
}

/*!
 * Load and validate the user's secret parameter.
 *
 * @param[in]	identifier for the secret key in the keystore.
 * @param[in]	serialized blob that represents the secret parameters.
 * @param[in]	an optional password to derive a key for decrypting the serialized blob.
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextSchemeCPA::loadUserSecretParams(const string &skID,
                                       OpenABEByteString &skBlob) {
  return this->loadKey(skID, skBlob, KEY_TYPE_SECRET);
}


/*!
 * Delete a key from the in-memory keystore given a key identifier.
 *
 * @param[in]   a string key identifier.
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCPA::deleteKey(const string keyID) {
  return this->m_KEM_->getKeystore()->deleteKey(keyID);
}

bool OpenABEContextSchemeCPA::checkSecretKey(const string keyID) {
  return this->m_KEM_->getKeystore()->checkSecretKey(keyID);
}

/*!
 * Generate a public/private keypair for a given user.
 *
 * @param[in]   functional input of the key to be created (either attribute list or policy).
 * @param[in]   parameter ID of the master public key.
 * @param[in]   parameter ID of the master secret key.
 * @param[in]   parameter ID of the global public key (optional).
 * @param[in]   parameter ID of the global identifier (optional).
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCPA::keygen(OpenABEFunctionInput *keyInput, const string &keyID,
                         const string &mpkID, const string &mskID,
                         const string &gpkID, const string &GID) {
  return this->m_KEM_->generateDecryptionKey(keyInput, keyID, mpkID, mskID,
                                             gpkID, GID);
}

/*!
 * Generate and encrypt a symmetric key using the key encapsulation mode
 * of the underlying KEM scheme. Use the symmetric key with PRNG to encrypt
 * the plaintext. Return the ciphertext.
 *
 * @param[in]   random number generator to use during encryption (it is optional: could be set to NULL here).
 * @param[in]	master public key identifier in keystore for the recipient (assumes it's already in keystore).
 * @param[in]   functional input of the underlying KEM context (either attribute list or policy).
 * @param[in]   the plaintext.
 * @param[out]	the ciphertext (must be allocated).
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCPA::encrypt(OpenABERNG *rng, const string &mpkID,
                          const OpenABEFunctionInput *encryptInput,
                          OpenABEByteString *plaintext, OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABESymKey> K(new OpenABESymKey);
  unique_ptr<OpenABERNG> PRNG = nullptr;
  unique_ptr<OpenABEByteString> y = nullptr;

  try {
    ASSERT_NOTNULL(plaintext);
    ASSERT_NOTNULL(ciphertext);
    // generate Key Encapsulation for access structure under MPK
    result = this->m_KEM_->encryptKEM(rng, mpkID, encryptInput,
                                      DEFAULT_SYM_KEY_BYTES, K, ciphertext);
    ASSERT(result == OpenABE_NOERROR, result);
    // compute H_0(K) to get initial seed for PRNG
    uint32_t target_len = plaintext->size();
    OpenABEByteString hashK = this->m_KEM_->getPairing()->hashFromBytes(
        K->getKeyBytes(), OpenABE_CTR_DRBG_NONCELEN, SCHEME_HASH_FUNCTION);

    // instantiate PRNG with entropy from K
    PRNG.reset(new OpenABECTR_DRBG(K->getInternalPtr(), K->getLength()));
    // hashK buffer as initial seed (or plaintext)
    PRNG->setSeed(hashK);
    // extract length bytes from RNG then XOR with plaintext
    y.reset(new OpenABEByteString);
    PRNG->getRandomBytes(y.get(), target_len);
    // y = y XOR plaintext
    *y ^= *plaintext;
    ciphertext->setComponent("_ED", y.get()); // encryptedData

    // cout << "encryptedData: " << y->toHex() << endl;
    hashK.zeroize();
    K->zeroize();
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

 /*!
  * Decrypt a symmetric key using the key encapsulation mode
  * of the underlying scheme. Use the key with PRNG to decrypt
  * the other half of the ciphertext payload. Return the plaintext.
  *
  * @param[in]   master public key identifier of the sender (assumes it's already in keystore).
  * @param[in]   key identifier of recipient (assumes it's already in keystore).
  * @param[out]  OpenABEByteString object to store resulting plaintext (assumes it's already allocated).
  * @param[in]   the ciphertext.
  * @return  An error code or OpenABE_NOERROR.
  */
OpenABE_ERROR
OpenABEContextSchemeCPA::decrypt(const string &mpkID, const string &keyID,
                          OpenABEByteString *plaintext, OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABESymKey> K(new OpenABESymKey);
  unique_ptr<OpenABERNG> PRNG = nullptr;

  try {
    result = this->m_KEM_->decryptKEM(mpkID, keyID, ciphertext,
                                      DEFAULT_SYM_KEY_BYTES, K);
    ASSERT(result == OpenABE_NOERROR, result);
    // retrieve encrypted data
    OpenABEByteString *encMessage =
        ciphertext->getByteString("_ED"); // encryptedData
    if (encMessage == nullptr) {
      throw OpenABE_ERROR_INVALID_INPUT;
    }

    uint32_t target_len = encMessage->size();
    OpenABEByteString hashK = this->m_KEM_->getPairing()->hashFromBytes(
        K->getKeyBytes(), OpenABE_CTR_DRBG_NONCELEN, SCHEME_HASH_FUNCTION);
    // instantiate PRNG with the K from encryptKEM
    PRNG.reset(new OpenABECTR_DRBG(K->getInternalPtr(), K->getLength()));
    // hashK buffer as initial seed (or plaintext)
    PRNG->setSeed(hashK);

    // extract length bytes from RNG then XOR with plaintext
    plaintext->clear();
    PRNG->getRandomBytes(plaintext, target_len);

    // PRNG(K, l) XOR *encMessage
    *plaintext ^= *encMessage;
    // zeroize
    hashK.zeroize();
    K->zeroize();
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}
}
