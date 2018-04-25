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
/// \file   zcontextpke.cpp
///
/// \brief  Implementation for OpenABE context PKE schemes.
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEContextPKE class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEContextPKE base class.
 *
 */
OpenABEContextPKE::OpenABEContextPKE() : OpenABEContext() {}

/*!
 * Destructor for the OpenABEContextPKE base class.
 *
 */
OpenABEContextPKE::~OpenABEContextPKE() {}

/*!
 * Initialize the elliptic curve structure in underlying math library
 *
 * @param   String for initializing the group parameters
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextPKE::initializeCurve(const string groupParams) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  if (this->m_EllipticCurve_ != nullptr) {
    return result;
  }

  // Instantiate a OpenABE elliptic curve object with the given parameters
  this->m_EllipticCurve_.reset(OpenABE_createNewEllipticCurve(groupParams));
  if (this->m_EllipticCurve_ == nullptr) {
    throw OpenABE_ERROR_INVALID_GROUP_PARAMS;
  }

  return result;
}

/*!
 * Select the elliptic curve based on the given security level.
 *
 * @param[in]   Security level for the scheme.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextPKE::generateParams(OpenABESecurityLevel securityLevel) {
  string ecParams = OpenABE_ECParamsForSecurityLevel(securityLevel);

  if (ecParams == "") {
    return OpenABE_ERROR_INVALID_GROUP_PARAMS;
  }

  return this->generateParams(ecParams);
}


/********************************************************************************
 * Implementation of the OpenABEContextOPDH class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEContextOPDH base class.
 *
 */
OpenABEContextOPDH::OpenABEContextOPDH(std::unique_ptr<OpenABERNG> rng) : OpenABEContextPKE() {
  // set the random number generator on initialization
  this->m_RNG_ = std::move(rng);
  this->algID = OpenABE_SCHEME_PK_OPDH;
}

/*!
 * Destructor for the OpenABEContextOPDH base class.
 */
OpenABEContextOPDH::~OpenABEContextOPDH() {}

/*!
 * Generate parameters of the elliptic curve based on a string identifier.
 *
 * @param[in]   Specific elliptic curve to load for the scheme.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextOPDH::generateParams(const string groupParams) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    // Instantiate a OpenABE elliptic curve object with the given parameters
    this->initializeCurve(groupParams);
  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

/*!
 * Generate a public/private keypair for a given user.
 *
 * @param[in]   identifier for the decryption key to be created.
 * @param[in]   parameter ID of the Public Key
 * @param[in]   parameter ID of the Secret Key
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextOPDH::generateDecryptionKey(const string &keyID, const string &pkID,
                                      const string &skID) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEKey> PK = nullptr, SK = nullptr;
  OpenABEByteString uid;
  OpenABERNG *myRNG = this->getRNG();

  try {
    // Assert that the RNG has been set
    ASSERT_NOTNULL(myRNG);
    // generate a random UID for PK/SK
    myRNG->getRandomBytes(&uid, UID_LEN);
    // select generator of the curve
    G_t g = this->getECCurve()->getGenerator();
    // generate static public and private keys
    ZP_t a = this->getECCurve()->randomZP(myRNG);
    // A = g ^ a
    G_t A = g.exp(a);

    // initialize containers for the keys
    PK.reset(new OpenABEKey(this->getECCurve()->getCurveID(), OpenABE_SCHEME_PK_OPDH,
                        keyID, &uid));
    SK.reset(new OpenABEKey(this->getECCurve()->getCurveID(), OpenABE_SCHEME_PK_OPDH,
                        keyID, &uid));

    PK->setComponent("A", &A);
    SK->setComponent("a", &a);

    // Add (MPK, MSK) to the keystore
    this->getKeystore()->addKey(pkID, PK, KEY_TYPE_PUBLIC);
    this->getKeystore()->addKey(skID, SK, KEY_TYPE_SECRET);

  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

/*!
 * Generate and encrypt a symmetric key using the key encapsulation mode
 * of the scheme. Return the key and ciphertext.
 *
 * @param[in]   random number generator to use during encryption (it is optional: could be set to NULL here).
 * @param[in]	public key identifier in keystore for the recipient (assumes it's already in keystore).
 * @param[in]   public key UID for sender.
 * @param[in]   length of the symmetric key.
 * @param[out]  symmetric key to be returned (must be allocated).
 * @param[out]	PKE ciphertext (must be allocated).
 * @return  An error code or OpenABE_NOERROR.
 */

OpenABE_ERROR
OpenABEContextOPDH::encryptKEM(OpenABERNG *rng, const string &pkID,
                           OpenABEByteString *senderID, uint32_t keyBitLen,
                           const std::shared_ptr<OpenABESymKey> &key,
                           OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABERNG *myRNG = this->getRNG();

  try {
    // check inputs
    ASSERT_NOTNULL(senderID);
    ASSERT_NOTNULL(ciphertext);
    ASSERT_NOTNULL(key);

    // check if the RNG has been set or not
    if (rng != nullptr) {
      myRNG = rng;
    }
    ASSERT_NOTNULL(myRNG);
    // load the recipient's public key
    shared_ptr<OpenABEKey> PK = this->getKeystore()->getPublicKey(pkID);
    if (PK == nullptr) {
      throw OpenABE_ERROR_MISSING_RECEIVER_PUBLIC_KEY;
    }
    // select generator of the curve
    G_t g = this->getECCurve()->getGenerator();
    // select ephemeral private keyL e <-$- ZP
    ZP_t e = this->getECCurve()->randomZP(myRNG);
    // compute ephemeral public key: C = g^e
    G_t C = g.exp(e);
    // store C in ciphertext
    ciphertext->setComponent("C", &C);

    // compute P = A ^ e => shared key: g^(a*e)
    G_t *A = PK->getG_t("A");
    ASSERT_NOTNULL(A);

    G_t P = A->exp(e);
    ZP_t x, y;
    P.get(x, y);
    OpenABEByteString Z = x.getByteString();

    // compute the metadata
    OpenABEByteString kdfMetadata;
    // kdf_metadata required: AlgID || ID_Sender || ID_Recipient
    kdfMetadata.insertFirstByte(OpenABE_SCHEME_PK_OPDH);
    kdfMetadata = kdfMetadata + *senderID + PK->getUID();

    unique_ptr<OpenABEKDF> kdf(new OpenABEKDF);
    OpenABEByteString DerivedKeyMaterial =
        kdf->DeriveKey(Z, keyBitLen, kdfMetadata);
    // return the derived key material
    key->setSymmetricKey(DerivedKeyMaterial);
    // set the ciphertext header (curve ID, scheme ID, etc)
    ciphertext->setHeader(this->getECCurve()->getCurveID(), OpenABE_SCHEME_PK_OPDH,
                          myRNG);
    // clear memory
    DerivedKeyMaterial.zeroize();
    kdfMetadata.clear();
    Z.clear();
  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

/*!
 * Decrypt a symmetric key using the key encapsulation mode
 * of the scheme. Return the key.
 *
 * @param[in]   public key identifier of the sender (assumes it's already in keystore).
 * @param[in]   secret key identifier of recipient (assumes it's already in keystore).
 * @param[in]   PKE ciphertext.
 * @param[out]  symmetric key to be returned.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextOPDH::decryptKEM(const string &pkID, const string &skID,
                           OpenABECiphertext *ciphertext, uint32_t keyBitLen,
                           const std::shared_ptr<OpenABESymKey> &key) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEKey> SK = nullptr, PK = nullptr;
  OpenABEByteString senderID;
  unique_ptr<OpenABEKDF> kdf = nullptr;
  // compute the metadata
  OpenABEByteString kdfMetadata;
  try {
    // check inputs
    ASSERT_NOTNULL(ciphertext);
    ASSERT_NOTNULL(key);

    // load the sender's public key
    PK = this->getKeystore()->getPublicKey(pkID);
    if (PK == nullptr) {
      throw OpenABE_ERROR_MISSING_SENDER_PUBLIC_KEY;
    }
    senderID = PK->getUID();

    // load the recipient's private key
    SK = this->getKeystore()->getSecretKey(skID);
    if (SK == nullptr) {
      throw OpenABE_ERROR_MISSING_RECEIVER_PRIVATE_KEY;
    }

    // compute C ^ (recipient's private key)
    // to obtain the shared key
    G_t *C = ciphertext->getG_t("C");
    ASSERT_NOTNULL(C);
    ZP_t *a = SK->getZP_t("a");
    ASSERT_NOTNULL(a);
    G_t P = C->exp(*a);
    // extract x-coordinate from group element P
    ZP_t x, y;
    P.get(x, y);
    OpenABEByteString Z = x.getByteString();

    // kdf_metadata required: AlgID || ID_Sender || ID_Recipient
    kdfMetadata.insertFirstByte(OpenABE_SCHEME_PK_OPDH);
    kdfMetadata = kdfMetadata + senderID + SK->getUID();

    kdf.reset(new OpenABEKDF);
    OpenABEByteString DerivedKeyMaterial =
        kdf->DeriveKey(Z, keyBitLen, kdfMetadata);

    // return the derived key material
    key->setSymmetricKey(DerivedKeyMaterial);

    // clear memory
    DerivedKeyMaterial.zeroize();
    kdfMetadata.zeroize();
    Z.zeroize();

  } catch (OpenABE_ERROR &err) {
    result = err;
  }

  return result;
}

/*!
 *
 * Section 5.6.2.5 ECC Full Public Key Validation Routine.
 *
 * @param[in]   A OpenABEKey public key to be validated.
 * @return  true or false.
 */
bool OpenABEContextOPDH::validatePublicKey(const std::shared_ptr<OpenABEKey> &key) {
  ASSERT_NOTNULL(key);
  G_t *A = key->getG_t("A");
  /* make sure element exists in OpenABEKey structure */
  ASSERT_NOTNULL(A);

  /* retrieve the order of the EC points */
  ZP_t p = this->getECCurve()->getGroupOrder();
  ZP_t pMin1 = p;
  pMin1 -= 1;

  /* 1. verify that public key Q is not the point at infinity O
     also, partial check of the public key for an invalid range in the EC group
     */
  if (this->getECCurve()->isAtInfinity(*A)) {
    return false;
  }

  /* 2. verify that Q->x and Q->y are integers in the interval [0,p-1] in the
     case
     that q is an odd prime p */
  ZP_t x, y;
  A->get(x, y);
  if (x >= pMin1 || y >= pMin1) {
    return false;
  }

  /* 3. Ensures that the public key is on the correct elliptic curve. */
  if (!this->getECCurve()->isOnCurve(*A)) {
    return false;
  }

  /* 4. Ensures that the public key has the correct order. Verify that n*Q ==
   * infinity. */
  // Also, ensures that the public key is in the correct range in the
  // correct EC subgroup, that is, it is in the
  // correct EC subgroup and is not the identity element.
  G_t R = A->exp(p);
  if (!this->getECCurve()->isAtInfinity(R)) {
    return false;
  }

  return true;
}

/*!
 *
 * Section 5.6.2.5 ECC Full Private Key Validation Routine.
 *
 * @param[in]   A OpenABEKey private key to be validated.
 * @return  true or false.
 */
bool OpenABEContextOPDH::validatePrivateKey(const std::shared_ptr<OpenABEKey> &key) {
  ASSERT_NOTNULL(key);
  ZP_t *a = key->getZP_t("a");
  ASSERT_NOTNULL(a);
  /* retrieve the order of the EC points */
  ZP_t p = this->getECCurve()->getGroupOrder();
  ZP_t pMin1 = p;
  pMin1 -= 1;

  if (*a >= pMin1) {
    return false;
  }

  return true;
}

/********************************************************************************
 * Implementation of the OpenABEContextSchemePKE class
 ********************************************************************************/

/*!
 * Constructor for the OpenABEContextSchemePKE base class.
 *
 */
OpenABEContextSchemePKE::OpenABEContextSchemePKE(std::unique_ptr<OpenABEContextPKE> kem) {
  this->m_KEM_ = std::move(kem);
}

/*!
 * Destructor for the OpenABEContextSchemePKE base class.
 *
 */
OpenABEContextSchemePKE::~OpenABEContextSchemePKE() {}

/*!
 * Generate parameters of the elliptic curve based on a string identifier.
 *
 * @param[in]   Specific elliptic curve to load for the scheme.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemePKE::generateParams(const string groupParams) {
  return this->m_KEM_->generateParams(groupParams);
}

/*!
 * Generate a public/private keypair for a given user.
 *
 * @param[in]   identifier for the decryption key to be created.
 * @param[in]   parameter ID of the Public Key
 * @param[in]   parameter ID of the Secret Key
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemePKE::keygen(const string &keyID, const string &pkID,
                            const string &skID) {
  return this->m_KEM_->generateDecryptionKey(keyID, pkID, skID);
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
OpenABEContextSchemePKE::exportKey(const string &keyID, OpenABEByteString &keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  OpenABEByteString tmpKeyBlob;

  try {
    // Attempt to export the given keyID to a temp keyBlob output buffer
    if (OpenABE_exportKey(this->m_KEM_->getKeystore(), keyID, &tmpKeyBlob) !=
        OpenABE_NOERROR) {
      throw OpenABE_ERROR_INVALID_INPUT;
    }

    // Just set the keyBlob
    keyBlob.clear();
    keyBlob += tmpKeyBlob;
    // Clear the temp buffer
    tmpKeyBlob.zeroize();
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

/*!
 * Load a public key into the keystore given a key identifier and blob of bytes.
 *
 * @param[in]   identifier for the key.
 * @param[in]   a OpenABEByteString to load the key header/body.
 * @param[in]   a password to decrypt the key blob under (optional).
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemePKE::loadPublicKey(const string &keyID, OpenABEByteString &keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEKey> PK = nullptr;

  try {
    // Parse the result into a OpenABEKey structure
    OpenABEByteString outputKeyBytes;
    PK = this->m_KEM_->getKeystore()->constructKeyFromBytes(keyID, keyBlob,
                                                            outputKeyBytes);
    if (PK == nullptr) {
      throw OpenABE_ERROR_INVALID_INPUT;
    }

    // Initialize the curve if ec parameters are not set
    if (this->m_KEM_->getECCurve() == nullptr) {
      // Set parameters based on the PK's curve ID
      this->m_KEM_->initializeCurve(
          OpenABE_convertECCurveIDToString(PK->getCurveID()));
    }

    if (PK->getCurveID() != this->m_KEM_->getECCurve()->getCurveID() ||
        PK->getAlgorithmID() != this->m_KEM_->getAlgorithmID()) {
      throw OpenABE_ERROR_INVALID_KEY_HEADER;
    }

    // Now we can deserialize the body of the key
    PK->setGroup(this->m_KEM_->getECCurve()->getGroup());
    PK->loadKeyFromBytes(outputKeyBytes);

    // Perform validation on the public OpenABEKey structure
    if (this->m_KEM_->validatePublicKey(PK)) {
      // If all goes well, then add the constructed key to the keystore
      this->m_KEM_->getKeystore()->addKey(keyID, PK, KEY_TYPE_PUBLIC);
    } else {
      throw OpenABE_ERROR_INVALID_PARAMS;
    }

  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

/*!
 * Load a private key into the keystore given a key identifier and blob of bytes.
 *
 * @param[in]   identifier for the key.
 * @param[in]   a OpenABEByteString to load the key header/body.
 * @param[in]   a password to decrypt the key blob under (optional).
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemePKE::loadPrivateKey(const string &keyID, OpenABEByteString &keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEKey> SK = nullptr;

  try {
    // Parse the keyBlob into a OpenABEKey structure
    OpenABEByteString outputKeyBytes;
    SK = this->m_KEM_->getKeystore()->constructKeyFromBytes(keyID, keyBlob,
                                                            outputKeyBytes);
    if (SK == nullptr) {
      throw OpenABE_ERROR_INVALID_INPUT;
    }
    // Initialize the curve if ec parameters are not set
    if (this->m_KEM_->getECCurve() == nullptr) {
      // Set parameters based on the PK's curve ID
      this->m_KEM_->initializeCurve(
          OpenABE_convertECCurveIDToString(SK->getCurveID()));
    }

    if (SK->getCurveID() != this->m_KEM_->getECCurve()->getCurveID() ||
        SK->getAlgorithmID() != this->m_KEM_->getAlgorithmID()) {
      throw OpenABE_ERROR_INVALID_KEY_HEADER;
    }

    // Now we can deserialize the body of the key
    SK->setGroup(this->m_KEM_->getECCurve()->getGroup());
    SK->loadKeyFromBytes(outputKeyBytes);
    // Perform validation on the private OpenABEKey
    if (this->m_KEM_->validatePrivateKey(SK)) {
      // If all goes well, then add the constructed key to the keystore
      this->m_KEM_->getKeystore()->addKey(keyID, SK, KEY_TYPE_SECRET);
    } else {
      throw OpenABE_ERROR_INVALID_PARAMS;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

/*!
 * Delete a key from the in-memory keystore given a key identifier.
 *
 * @param[in]   a string key identifier.
 * @return      An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemePKE::deleteKey(const string &keyID) {
  return this->m_KEM_->getKeystore()->deleteKey(keyID);
}

/*!
 * Generate and encrypt a symmetric key using the key encapsulation mode
 * of the underlying scheme. Use the symmetric key with AES-GCM to encrypt
 * the plaintext. Return the ciphertext.
 *
 * @param[in]   random number generator to use during encryption (it is optional: could be set to NULL here).
 * @param[in]	public key identifier in keystore for the recipient (assumes it's already in keystore).
 * @param[in]   public key UID for sender.
 * @param[in]   the plaintext.
 * @param[out]	PKE ciphertext (must be allocated).
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemePKE::encrypt(OpenABERNG *rng, const string &pkID,
                             const string &senderpkID, const string &plaintext,
                             OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEKey> senderPK = nullptr;
  OpenABEByteString senderID, keyBytes, ctHdr, iv, ct, tag;
  shared_ptr<OpenABESymKey> key(new OpenABESymKey);
  unique_ptr<oabe::crypto::OpenABESymKeyAuthEnc> authEnc = nullptr;

  try {
    ASSERT_NOTNULL(ciphertext);
    // make sure plaintext size > 0
    ASSERT(plaintext.size() > 0, OpenABE_ERROR_NO_PLAINTEXT_SPECIFIED);

    // Get PK of sender (assumes it has already been loaded)
    senderPK = this->m_KEM_->getKeystore()->getPublicKey(senderpkID);
    if (senderPK == nullptr) {
      throw OpenABE_ERROR_MISSING_SENDER_PUBLIC_KEY;
    }
    senderID = senderPK->getUID();
    // Returns a ciphertext and a symmetric key
    result = this->m_KEM_->encryptKEM(rng, pkID, &senderID,
                                      DEFAULT_SYM_KEY_BITS, key, ciphertext);
    // Propagate errors from encryptKEM
    ASSERT(result == OpenABE_NOERROR, result);

    // Instantiate an auth enc scheme with the symmetric key
    keyBytes = key->getKeyBytes();
    authEnc.reset(
        new oabe::crypto::OpenABESymKeyAuthEnc(DEFAULT_AES_SEC_LEVEL, keyBytes));
    // Obtain header from ciphertext
    ciphertext->getHeader(ctHdr);
    // Embed the header of the ciphertext as AAD
    authEnc->setAddAuthData(ctHdr);
    // Encrypt
    authEnc->encrypt(plaintext, &iv, &ct, &tag);
    // Store symmetric ciphertext
    ciphertext->setComponent("IV", &iv);
    ciphertext->setComponent("CT", &ct);
    ciphertext->setComponent("Tag", &tag);
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  key->zeroize();
  keyBytes.zeroize();
  return result;
}

/*!
 * Decrypt a symmetric key using the key encapsulation mode
 * of the underlying scheme. Use the key with AES-GCM to decrypt
 * the other half of the ciphertext payload. Return the plaintext.
 *
 * @param[in]   public key identifier of the sender (assumes it's already in
 * keystore).
 * @param[in]   secret key identifier of recipient (assumes it's already in
 * keystore).
 * @param[out]  OpenABEByteString object to store resulting plaintext (assumes it's
 * already allocated).
 * @param[in]   PKE ciphertext.
 * @return  An error code or OpenABE_NOERROR.
 */
OpenABE_ERROR
OpenABEContextSchemePKE::decrypt(const string &pkID, const string &skID,
                             string &plaintext, OpenABECiphertext *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABESymKey> key(new OpenABESymKey);
  unique_ptr<oabe::crypto::OpenABESymKeyAuthEnc> authEnc = nullptr;
  OpenABEByteString *iv = nullptr, *ct = nullptr, *tag = nullptr;
  OpenABEByteString ctHdr, keyBytes;

  try {
    result = this->m_KEM_->decryptKEM(pkID, skID, ciphertext,
                                      DEFAULT_SYM_KEY_BITS, key);
    // propagate errors from decryptKEM
    ASSERT(result == OpenABE_NOERROR, result);

    // construct the 'ct' structure from ciphertext then decrypt
    iv = ciphertext->getByteString("IV");
    ASSERT_NOTNULL(iv);
    ct = ciphertext->getByteString("CT");
    ASSERT_NOTNULL(ct);
    tag = ciphertext->getByteString("Tag");
    ASSERT_NOTNULL(tag);

    // Instantiate an auth enc scheme with the symmetric key
    keyBytes = key->getKeyBytes();
    authEnc.reset(
        new oabe::crypto::OpenABESymKeyAuthEnc(DEFAULT_AES_SEC_LEVEL, keyBytes));
    // embed the header of the ciphertext
    ciphertext->getHeader(ctHdr);
    // embed the header of the ciphertext as AAD
    authEnc->setAddAuthData(ctHdr);

    if (!authEnc->decrypt(plaintext, iv, ct, tag)) {
      throw OpenABE_ERROR_DECRYPTION_FAILED;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  key->zeroize();
  keyBytes.zeroize();
  return result;
}
}
