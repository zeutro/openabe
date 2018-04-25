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
/// \file   zcontextcca.cpp
///
/// \brief  Base class definition for OpenABE context CCA schemes
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace std;
using namespace oabe::crypto;

/********************************************************************************
 * Implementation of the OpenABEContextCCA class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEContextCCA base class.
 *
 */
OpenABEContextCCA::OpenABEContextCCA(unique_ptr<OpenABEContextSchemeCPA> scheme_)
    : OpenABEContextABE() {
  if (scheme_) {
    this->abeSchemeContext = move(scheme_);
  } else {
    /* throw error */
    throw OpenABE_ERROR_INVALID_INPUT;
  }
}

/*!
 * Destructor for the OpenABEContextCCA base class.
 *
 */

OpenABEContextCCA::~OpenABEContextCCA() {}

/*!
 * Export a key from the keystore given the key identifier.
 *
 * @param[in]   identifier for the key.
 * @param[out]  an allocated OpenABEByteString to store the exported key header/body.
 * @param[in]   a password to encrypt the exported key under (optional).
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextCCA::exportKey(const string &keyID, OpenABEByteString &keyBlob) {
  return this->abeSchemeContext->exportKey(keyID, keyBlob);
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
OpenABEContextCCA::loadMasterPublicParams(const string &mpkID,
                                      OpenABEByteString &mpkBlob) {
  return this->abeSchemeContext->loadMasterPublicParams(mpkID, mpkBlob);
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
OpenABEContextCCA::loadMasterSecretParams(const string &mskID,
                                      OpenABEByteString &mskBlob) {
  return this->abeSchemeContext->loadMasterSecretParams(mskID, mskBlob);
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
OpenABEContextCCA::loadUserSecretParams(const string &skID, OpenABEByteString &skBlob) {
  return this->abeSchemeContext->loadUserSecretParams(skID, skBlob);
}


/*!
 * Delete a key from the in-memory keystore given a key identifier.
 *
 * @param[in]   a string key identifier.
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextCCA::deleteKey(const string keyID) {
  return this->abeSchemeContext->deleteKey(keyID);
}

bool
OpenABEContextCCA::checkSecretKey(const string keyID)
{
    return this->abeSchemeContext->checkSecretKey(keyID);
}

OpenABE_ERROR
OpenABEContextCCA::generateGlobalParams(const string groupParams,
                                    const string &gpkID) {
  return this->abeSchemeContext->generateGlobalParams(groupParams, gpkID);
}

OpenABE_ERROR
OpenABEContextCCA::generateAuthorityParams(const string &gpkID,
                                       const string &auth_mpkID,
                                       const string &auth_mskID) {
  return this->abeSchemeContext->generateAuthorityParams(gpkID, auth_mpkID,
                                                         auth_mskID);
}

OpenABEByteString*
OpenABEContextCCA::getHashKey(const string &mpkID) {
	return this->abeSchemeContext->getHashKey(mpkID);
}

/********************************************************************************
 * Implementation of the OpenABEContextGenericCCA class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEContextGenericCCA base class.
 *
 */
OpenABEContextGenericCCA::OpenABEContextGenericCCA(unique_ptr<OpenABEContextSchemeCPA> scheme)
    : OpenABEContextCCA(move(scheme)) {}

/*!
 * Destructor for the OpenABEContextCCA base class.
 *
 */

OpenABEContextGenericCCA::~OpenABEContextGenericCCA() {}

OpenABE_ERROR
OpenABEContextGenericCCA::generateParams(const string groupParams,
                                     const string &mpkID, const string &mskID) {
  return this->abeSchemeContext->generateParams(groupParams, mpkID, mskID);
}


/*!
 * Generate a decryption key for a given function input. This function
 * requires that the master secret parameters are available.
 *
 * @param[in] mpkID     - parameter ID of the Master Public Key
 * @param[in] mskID     - parameter ID of the Master Secret Key
 * @param[in] keyID     - parameter ID of the decryption key to be created
 * @param[in] keyInput  - A OpenABEAttributeList structure for the key to be constructed
 * @return              - An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextGenericCCA::generateDecryptionKey(
    OpenABEFunctionInput *keyInput, const string &keyID, const string &mpkID,
    const string &mskID, const string &gpkID, const string &GID) {
  return this->abeSchemeContext->keygen(keyInput, keyID, mpkID, mskID, gpkID,
                                        GID);
}

/*!
 * Generate and encrypt a symmetric key using the key encapsulation mode
 * of the scheme. Use resulting key to encrypt randomness and plaintext.
 * Return the ciphertext.
 *
 * @param   Parameters ID for the public master parameters.
 * @param   Function input for the encryption.
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextGenericCCA::encryptKEM(OpenABERNG *rng, const string &mpkID,
                                 const OpenABEFunctionInput *encryptInput,
                                 uint32_t keyByteLen,
                                 const std::shared_ptr<OpenABESymKey> &key,
                                 OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABERNG *myRNG = nullptr;
  unique_ptr<OpenABERNG> PRNG = nullptr;
  OpenABEByteString r, K, u, nonceU, concat;
  try {
    ASSERT_NOTNULL(encryptInput);
    ASSERT_NOTNULL(key);
    ASSERT_NOTNULL(ciphertext);
    if (rng == nullptr) {
      // expect the RNG to be set in constructor
      myRNG = this->getRNG();
    } else {
      // use the passed in RNG
      myRNG = rng;
    }
    // Assert that the RNG has been set
    ASSERT_NOTNULL(myRNG);

    // choose r
    myRNG->getRandomBytes(&r, keyByteLen);
    // cout << "r : " << r.toHex() << endl;

    // choose K
    myRNG->getRandomBytes(&K, keyByteLen);
    // cout << "K : " << K.toHex() << endl;

    // set M = r || K
    OpenABEByteString M = r + K;
    // r || K || A
    concat = M + encryptInput->toString();
    // uint32_t target_len = concat.size();

    // u = H_1(r || K || A)
    u = this->getPairing()->hashFromBytes(concat, keyByteLen,
                                          CCA_HASH_FUNCTION_ONE);
    // hashU = H_2(u)
    nonceU = this->getPairing()->hashFromBytes(u, OpenABE_CTR_DRBG_NONCELEN,
                                               CCA_HASH_FUNCTION_TWO);

    // construct a new PRNG
    // set the key and seed (or plaintext)
    PRNG.reset(new OpenABECTR_DRBG(u));
    PRNG->setSeed(nonceU);

    // compute ciphertext, C
    result = this->abeSchemeContext->encrypt(PRNG.get(), mpkID, encryptInput,
                                             &M, ciphertext);
    if (result != OpenABE_NOERROR) {
      OpenABE_LOG_AND_THROW("ABE Encryption failed.", OpenABE_ERROR_ENCRYPTION_ERROR);
    }

    // set the encapsulation key
    // by storing K in 'key' object
    key->setSymmetricKey(K);
  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

/*!
 * Decrypt a symmetric key using the generic transform
 * Return the key.
 *
 * @param   Parameters ID for the public master parameters.
 * @param   Identifier for the decryption key to be used.
 * @param   ABE ciphertext.
 * @param   Symmetric key to be returned.
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextGenericCCA::decryptKEM(const string &mpkID, const string &keyID,
                                 OpenABECiphertext *ciphertext, uint32_t keyByteLen,
                                 const std::shared_ptr<OpenABESymKey> &key) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString M;
  unique_ptr<OpenABERNG> PRNG = nullptr;
  unique_ptr<OpenABEFunctionInput> encryptInput = nullptr;
  unique_ptr<OpenABECiphertext> ciphertext2(new OpenABECiphertext);
  OpenABEByteString u, nonceU, concat;

  try {
    // fully decrypt the ciphertext and recover 'r' and 'M'
    ASSERT_NOTNULL(ciphertext);
    ASSERT_NOTNULL(key);
    result = this->abeSchemeContext->decrypt(mpkID, keyID, &M, ciphertext);
    if (result != OpenABE_NOERROR) {
      OpenABE_LOG_AND_THROW("ABE Decryption failed.", OpenABE_ERROR_DECRYPTION_FAILED);
    }

    // extract 'r' and 'K' from M
    OpenABEByteString r = M.getSubset(0, keyByteLen);
    OpenABEByteString K = M.getSubset(keyByteLen, keyByteLen);

    // retrieve inputs from ciphertext and recovered message
    encryptInput = getFunctionInput(ciphertext);
    if (encryptInput == nullptr) {
      OpenABE_LOG_AND_THROW("Failed to get functional input.",
                        OpenABE_ERROR_INVALID_INPUT);
    }
    // r' || K' || A
    concat = r + K + encryptInput->toString();
    // u = H_1(r' || K' || A)
    u = this->getPairing()->hashFromBytes(concat, keyByteLen,
                                          CCA_HASH_FUNCTION_ONE);
    // nonceU = H_2(u)
    nonceU = this->getPairing()->hashFromBytes(u, OpenABE_CTR_DRBG_NONCELEN,
                                               CCA_HASH_FUNCTION_TWO);

    // construct a new PRNG
    // set the key and seed (or plaintext)
    PRNG.reset(new OpenABECTR_DRBG(u));
    PRNG->setSeed(nonceU);

    // compute ciphertext, C
    result = this->abeSchemeContext->encrypt(
        PRNG.get(), mpkID, encryptInput.get(), &M, ciphertext2.get());
    // verification check
    if (*ciphertext == *ciphertext2) {
      key->setSymmetricKey(K);
    } else {
      OpenABE_LOG_AND_THROW("Failed ABE decryption verification check.",
                        OpenABE_ERROR_DECRYPTION_FAILED);
    }

  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

/********************************************************************************
 * Implementation of the OpenABEContextSchemeCCA class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEContextSchemeCCA base class.
 * Note: we add to
 */
OpenABEContextSchemeCCA::OpenABEContextSchemeCCA(unique_ptr<OpenABEContextCCA> kem_)
    : ZObject() {
  OpenABE_SCHEME scheme_type = OpenABE_SCHEME_NONE;
  // upgrade the scheme type according to input KEM type
  if (kem_->getSchemeType() == OpenABE_SCHEME_KP_GPSW) {
    scheme_type = OpenABE_SCHEME_KP_GPSW_CCA;
  } else if (kem_->getSchemeType() == OpenABE_SCHEME_CP_WATERS) {
    scheme_type = OpenABE_SCHEME_CP_WATERS_CCA;
  } else {
    /* unrecognized scheme type */
    throw OpenABE_ERROR_INVALID_INPUT;
  }
  this->m_KEM_ = move(kem_);
  this->m_KEM_->setSchemeType(scheme_type);
}

/*!
 * Destructor for the OpenABEContextABE base class.
 *
 */
OpenABEContextSchemeCCA::~OpenABEContextSchemeCCA() {}

/*!
 * Generate parameters of the pairing curve based on a string identifier.
 *
 * @param[in]   specific string identifier to instantiate the pairing curve.
 * @param[in]   a string identifier for the master public parameters.
 * @param[in]   a string identifier for the master secret parameters.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCCA::generateParams(const string groupParams,
                                    const string &mpkID, const string &mskID) {
  return this->m_KEM_->generateParams(groupParams, mpkID, mskID);
}

/*!
 * Generate global parameters of the pairing curve based on a string identifier.
 *
 * @param[in]   specific string identifier to instantiate the pairing curve.
 * @param[in]   a string identifier for the global public parameters.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCCA::generateGlobalParams(const string groupParams,
                                          const string &gpkID) {
  return this->m_KEM_->generateGlobalParams(groupParams, gpkID);
}

/*!
 * Generate authority parameters of the pairing curve based on a string identifier.
 *
 * @param[in]   specific string identifier to instantiate the pairing curve.
 * @param[in]   a string identifier for the authority's master public parameters.
 * @param[in]   a string identifier for the authority's master secret parameters.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCCA::generateAuthorityParams(const string &gpkID,
                                             const string &auth_mpkID,
                                             const string &auth_mskID) {
  return this->m_KEM_->generateAuthorityParams(gpkID, auth_mpkID, auth_mskID);
}

/*!
 * Export a key from the keystore given the key identifier.
 *
 * @param[in]   identifier for the key.
 * @param[out]  an allocated OpenABEByteString to store the exported key header/body.
 * @param[in]   a password to encrypt the exported key under (optional).
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCCA::exportKey(const string &keyID, OpenABEByteString &keyBlob) {
  return this->m_KEM_->exportKey(keyID, keyBlob);
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
OpenABEContextSchemeCCA::loadMasterPublicParams(const string &mpkID,
                                            OpenABEByteString &mpkBlob) {
  return this->m_KEM_->loadMasterPublicParams(mpkID, mpkBlob);
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
OpenABEContextSchemeCCA::loadMasterSecretParams(const string &mskID,
                                            OpenABEByteString &mskBlob) {
  return this->m_KEM_->loadMasterSecretParams(mskID, mskBlob);
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
OpenABEContextSchemeCCA::loadUserSecretParams(const string &skID,
                                          OpenABEByteString &skBlob) {
  return this->m_KEM_->loadUserSecretParams(skID, skBlob);
}


/*!
 * Delete a key from the in-memory keystore given a key identifier.
 *
 * @param[in]   a string key identifier.
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCCA::deleteKey(const string keyID) {
  return this->m_KEM_->deleteKey(keyID);
}

bool OpenABEContextSchemeCCA::checkSecretKey(const string keyID) {
  return this->m_KEM_->checkSecretKey(keyID);
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
OpenABEContextSchemeCCA::keygen(OpenABEFunctionInput *keyInput, const string &keyID,
                            const string &mpkID, const string &mskID,
                            const string &gpkID, const string &GID) {
  return this->m_KEM_->generateDecryptionKey(keyInput, keyID, mpkID, mskID,
                                             gpkID, GID);
}

/*!
 * Generate and encrypt a symmetric key using the key encapsulation mode
 * of the underlying KEM scheme. Use the symmetric key with AES-GCM to encrypt
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
OpenABEContextSchemeCCA::encrypt(const string &mpkID,
                             const OpenABEFunctionInput *encryptInput,
                             const string &plaintext,
                             OpenABECiphertext *ciphertext1,
                             OpenABECiphertext *ciphertext2) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  unique_ptr<OpenABERNG> rng(new OpenABERNG);
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey);
  OpenABEByteString ctHdr, symkeyBytes, iv, ct, tag;

  try {
    ASSERT_NOTNULL(ciphertext1);
    ASSERT_NOTNULL(ciphertext2);
    // make sure plaintext size > 0
    ASSERT(plaintext.size() > 0, OpenABE_ERROR_NO_PLAINTEXT_SPECIFIED);

    result =
        this->m_KEM_->encryptKEM(rng.get(), mpkID, encryptInput,
                                 DEFAULT_SYM_KEY_BYTES, symkey, ciphertext1);
    ASSERT(result == OpenABE_NOERROR, result);
    // instantiate an auth enc scheme with the symmetric key
    symkeyBytes = symkey->getKeyBytes();
    unique_ptr<oabe::crypto::OpenABESymKeyAuthEnc> authEnc(
        new oabe::crypto::OpenABESymKeyAuthEnc(DEFAULT_AES_SEC_LEVEL, symkeyBytes));
    // obtain header from ciphertext
    ciphertext1->getHeader(ctHdr);
    // embed the header of the ciphertext as AAD
    authEnc->setAddAuthData(ctHdr);
    // encrypt plaintext and store in iv/ct/tag
    authEnc->encrypt(plaintext, &iv, &ct, &tag);

    // Store symmetric ciphertext
    ciphertext2->setComponent("IV", &iv);
    ciphertext2->setComponent("CT", &ct);
    ciphertext2->setComponent("Tag", &tag);
    ciphertext2->setHeader(OpenABE_NONE_ID, OpenABE_SCHEME_AES_GCM, ciphertext1->getUID());
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  symkey->zeroize();
  symkeyBytes.zeroize();
  return result;
}

 /*!
  * Decrypt a symmetric key using the key encapsulation mode
  * of the underlying scheme. Use the key with AES-GCM to decrypt
  * the other half of the ciphertext payload. Return the plaintext.
  *
  * @param[in]   master public key identifier of the sender (assumes it's already in keystore).
  * @param[in]   key identifier of recipient (assumes it's already in keystore).
  * @param[out]  string reference to store resulting plaintext if decrypt successful.
  * @param[in]   the ciphertext.
  * @return  An error code or OpenABE_NOERROR.
  */
OpenABE_ERROR
OpenABEContextSchemeCCA::decrypt(const string &mpkID, const string &keyID,
                             string &plaintext, OpenABECiphertext *ciphertext1,
                             OpenABECiphertext *ciphertext2) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString ctHdr, symkeyBytes;
  OpenABEByteString *iv, *ct, *tag;
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey);
  unique_ptr<oabe::crypto::OpenABESymKeyAuthEnc> authEnc = nullptr;

  try {
    ASSERT_NOTNULL(ciphertext1);
    ASSERT_NOTNULL(ciphertext2);
    iv = ciphertext2->getByteString("IV");
    ASSERT_NOTNULL(iv);
    ct = ciphertext2->getByteString("CT");
    ASSERT_NOTNULL(ct);
    tag = ciphertext2->getByteString("Tag");
    ASSERT_NOTNULL(tag);

    // get the header of the input ciphertext
    ciphertext1->getHeader(ctHdr);
    // decrypt part 1 of the ciphertext (corresponds to ABE portion)
    result = this->m_KEM_->decryptKEM(mpkID, keyID, ciphertext1,
                                      DEFAULT_SYM_KEY_BYTES, symkey);
    // propagate errors from decryptKEM
    ASSERT(result == OpenABE_NOERROR, result);
    // apply AEAD to decrypt part 2 of the ciphertext (ciphertext header is
    // added as add auth data)
    symkeyBytes = symkey->getKeyBytes();
    authEnc.reset(
        new oabe::crypto::OpenABESymKeyAuthEnc(DEFAULT_AES_SEC_LEVEL, symkeyBytes));
    // embed the header of the ciphertext as AAD
    authEnc->setAddAuthData(ctHdr);
    // now attempt to decrypt
    if (!authEnc->decrypt(plaintext, iv, ct, tag)) {
      throw OpenABE_ERROR_DECRYPTION_FAILED;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  symkey->zeroize();
  symkeyBytes.zeroize();
  return result;
}

/********************************************************************************
 * Implementation of the OpenABEContextSchemeCCAWithATZN class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEContextSchemeCCA base class.
 * Note: we add to
 */
OpenABEContextSchemeCCAWithATZN::OpenABEContextSchemeCCAWithATZN(unique_ptr<OpenABEContextCCA> kem_)
    : ZObject() {
  OpenABE_SCHEME scheme_type = OpenABE_SCHEME_NONE;
  // upgrade the scheme type according to input KEM type
  if (kem_->getSchemeType() == OpenABE_SCHEME_KP_GPSW) {
    scheme_type = OpenABE_SCHEME_KP_GPSW_CCA;
  } else if (kem_->getSchemeType() == OpenABE_SCHEME_CP_WATERS) {
    scheme_type = OpenABE_SCHEME_CP_WATERS_CCA;
  } else {
    /* unrecognized scheme type */
    throw OpenABE_ERROR_INVALID_INPUT;
  }
  this->m_KEM_ = move(kem_);
  this->m_KEM_->setSchemeType(scheme_type);
}

/*!
 * Destructor for the OpenABEContextSchemeCCAWithATZN base class.
 *
 */
OpenABEContextSchemeCCAWithATZN::~OpenABEContextSchemeCCAWithATZN() {}

/*!
 * Generate parameters of the pairing curve based on a string identifier.
 *
 * @param[in]   specific string identifier to instantiate the pairing curve.
 * @param[in]   a string identifier for the master public parameters.
 * @param[in]   a string identifier for the master secret parameters.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCCAWithATZN::generateParams(const string groupParams,
                                    const string &mpkID, const string &mskID) {
  return this->m_KEM_->generateParams(groupParams, mpkID, mskID);
}

/*!
 * Generate global parameters of the pairing curve based on a string identifier.
 *
 * @param[in]   specific string identifier to instantiate the pairing curve.
 * @param[in]   a string identifier for the global public parameters.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCCAWithATZN::generateGlobalParams(const string groupParams,
                                          const string &gpkID) {
  return this->m_KEM_->generateGlobalParams(groupParams, gpkID);
}

/*!
 * Generate authority parameters of the pairing curve based on a string identifier.
 *
 * @param[in]   specific string identifier to instantiate the pairing curve.
 * @param[in]   a string identifier for the authority's master public parameters.
 * @param[in]   a string identifier for the authority's master secret parameters.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCCAWithATZN::generateAuthorityParams(const string &gpkID,
                                             const string &auth_mpkID,
                                             const string &auth_mskID) {
  return this->m_KEM_->generateAuthorityParams(gpkID, auth_mpkID, auth_mskID);
}

/*!
 * Export a key from the keystore given the key identifier.
 *
 * @param[in]   identifier for the key.
 * @param[out]  an allocated OpenABEByteString to store the exported key header/body.
 * @param[in]   a password to encrypt the exported key under (optional).
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCCAWithATZN::exportKey(const string &keyID, OpenABEByteString &keyBlob) {
  return this->m_KEM_->exportKey(keyID, keyBlob);
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
OpenABEContextSchemeCCAWithATZN::loadMasterPublicParams(const string &mpkID,
                                            OpenABEByteString &mpkBlob) {
  return this->m_KEM_->loadMasterPublicParams(mpkID, mpkBlob);
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
OpenABEContextSchemeCCAWithATZN::loadMasterSecretParams(const string &mskID,
                                            OpenABEByteString &mskBlob) {
  return this->m_KEM_->loadMasterSecretParams(mskID, mskBlob);
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
OpenABEContextSchemeCCAWithATZN::loadUserSecretParams(const string &skID,
                                          OpenABEByteString &skBlob) {
  return this->m_KEM_->loadUserSecretParams(skID, skBlob);
}


/*!
 * Delete a key from the in-memory keystore given a key identifier.
 *
 * @param[in]   a string key identifier.
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemeCCAWithATZN::deleteKey(const string keyID) {
  return this->m_KEM_->deleteKey(keyID);
}

bool OpenABEContextSchemeCCAWithATZN::checkSecretKey(const string keyID) {
  return this->m_KEM_->checkSecretKey(keyID);
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
OpenABEContextSchemeCCAWithATZN::keygen(OpenABEFunctionInput *keyInput, const string &keyID,
                            const string &mpkID, const string &mskID,
                            const string &gpkID, const string &GID) {
  return this->m_KEM_->generateDecryptionKey(keyInput, keyID, mpkID, mskID,
                                             gpkID, GID);
}

/*!
 * Generate and encrypt a symmetric key using the key encapsulation mode
 * of the underlying KEM scheme. Use the symmetric key with AES-GCM to encrypt
 * the plaintext. Return the ciphertext.
 *
 * @param[in]   random number generator to use during encryption (it is optional: could be set to NULL here).
 * @param[in]	master public key identifier in keystore for the recipient (assumes it's already in keystore).
 * @param[in]   functional input of the underlying KEM context (either attribute list or policy).
 * @param[out]	the ciphertext (must be allocated).
 * @param[out]  the sym key handle for encrypting data
 * @return  An error code or OpenABE_NOERROR.
 */
std::unique_ptr<OpenABESymKeyHandle>
OpenABEContextSchemeCCAWithATZN::encrypt(const string &mpkID,
                             const OpenABEFunctionInput *encryptInput,
                             OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  unique_ptr<OpenABERNG> rng(new OpenABERNG);
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey);
  unique_ptr<OpenABESymKeyHandle> keyHandle = nullptr;
  OpenABEByteString ctBlob, ctHash, symkeyBytes;

  try {
	ASSERT_NOTNULL(encryptInput);
    ASSERT_NOTNULL(ciphertext);

    result =
        this->m_KEM_->encryptKEM(rng.get(), mpkID, encryptInput,
                                 DEFAULT_SYM_KEY_BYTES, symkey, ciphertext);
    ASSERT(result == OpenABE_NOERROR, result);
    // retrieve the symmetric key
    symkeyBytes = symkey->getKeyBytes();
    // (1) get the ciphertext header and body bytes
    ciphertext->exportToBytes(ctBlob);
    // (2) compute hash of the ciphertext
    OpenABEByteString *k = this->m_KEM_->getHashKey(mpkID);
    ASSERT_NOTNULL(k);
    OpenABEComputeHash(*k, ctBlob, ctHash);
    // (3) create the key handle (from key and hash of ABE ciphertext)
    keyHandle.reset(new OpenABESymKeyHandleImpl(symkeyBytes, ctHash)); // no b64 encoding by default
  } catch (OpenABE_ERROR &error) {
      cerr << "CCAWithATZN::encrypt: " << OpenABE_errorToString(error) << endl;
  } catch (oabe::CryptoException& ex) {
      cerr << "CCAWithATZN::encrypt(CryptoException): " << ex.what() << endl;
  }

  symkey->zeroize();
  symkeyBytes.zeroize();
  return keyHandle;
}

 /*!
  * Decrypt a symmetric key using the key encapsulation mode
  * of the underlying scheme. Return the key handle.
  *
  * @param[in]   master public key identifier of the sender (assumes it's already in keystore).
  * @param[in]   key identifier of recipient (assumes it's already in keystore).
  * @param[out]  string reference to store resulting plaintext if decrypt successful.
  * @param[in]   the ciphertext.
  * @return  An error code or OpenABE_NOERROR.
  */
std::unique_ptr<OpenABESymKeyHandle>
OpenABEContextSchemeCCAWithATZN::decrypt(const string &mpkID, const string &keyID,
                             OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey);
  unique_ptr<OpenABESymKeyHandle> keyHandle = nullptr;
  OpenABEByteString ctBlob, ctHash, symkeyBytes;

  try {
    ASSERT_NOTNULL(ciphertext);
    // decrypt part 1 of the ciphertext (corresponds to ABE portion)
    result = this->m_KEM_->decryptKEM(mpkID, keyID, ciphertext,
                                      DEFAULT_SYM_KEY_BYTES, symkey);
    // propagate errors from decryptKEM
    ASSERT(result == OpenABE_NOERROR, result);
    // (0) retrieve the symmetric key
    symkeyBytes = symkey->getKeyBytes();
    // (1) get the ciphertext header and body bytes
    ciphertext->exportToBytes(ctBlob);
    // (2) compute hash of the ciphertext
    OpenABEByteString *k = this->m_KEM_->getHashKey(mpkID);
    ASSERT_NOTNULL(k);
    OpenABEComputeHash(*k, ctBlob, ctHash);
    // (3) create the key handle (from key and hash of ABE ciphertext)
    keyHandle.reset(new OpenABESymKeyHandleImpl(symkeyBytes, ctHash)); // no b64 encoding by default
  } catch (OpenABE_ERROR &error) {
      cerr << "CCAWithATZN::decrypt: " << OpenABE_errorToString(error) << endl;
  } catch (oabe::CryptoException& ex) {
      cerr << "CCAWithATZN::decrypt(CryptoException): " << ex.what() << endl;
  }

  symkey->zeroize();
  symkeyBytes.zeroize();
  return keyHandle;
}


}
