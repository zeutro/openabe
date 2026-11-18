///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// [license header unchanged]
///
/// \file   zcontextpksig.cpp
///
/// \brief  Implementation for OpenABE context PKSIG schemes.
///         Ported to OpenSSL 4.0 (EC_KEY/EC_GROUP API removed).
///
/// \author J. Ayo Akinyele
///

#include <fstream>
#include <iostream>
#include <openabe/openabe.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEContextPKSIG class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEContextPKSIG base class.
 *
 */
OpenABEContextPKSIG::OpenABEContextPKSIG() : OpenABEContext() {
  // curveName is a std::string, default-initialized to ""
}

/*!
 * Destructor for the OpenABEContextPKSIG base class.
 *
 */
OpenABEContextPKSIG::~OpenABEContextPKSIG() {
  // Nothing to free: curveName is a std::string (RAII)
}

OpenABE_ERROR OpenABEContextPKSIG::initializeCurve(const std::string groupParams) {
  try {
    if (this->curveName.empty()) {
      // Previously called generateECCurveParameters(&this->group, groupParams)
      // which created an EC_GROUP. In OpenSSL 4.0 we just store the curve
      // name string and pass it to EVP_PKEY_CTX at key-generation time.
      //
      // OpenABE uses its own names ("NIST_P256", ...): map them to the
      // OpenSSL short name via the NID (e.g. "prime256v1").
      if (groupParams.empty()) {
        throw OpenABE_ERROR_INVALID_GROUP_PARAMS;
      }
      int nid = OpenABE_convertStringToNID(groupParams);
      const char* sn = OBJ_nid2sn(nid);
      if (sn == nullptr) {
        throw OpenABE_ERROR_INVALID_GROUP_PARAMS;
      }
      this->curveName = sn;
    }
  } catch (OpenABE_ERROR& error) {
    return error;
  }

  return OpenABE_NOERROR;
}

OpenABE_ERROR OpenABEContextPKSIG::generateParams(const std::string groupParams) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    // Initialize the curve (if not already)
    this->initializeCurve(groupParams);

    // NOTE: In OpenSSL 4.0, named curves automatically embed their name in
    // serialised keys (SubjectPublicKeyInfo / PKCS#8). There is no need to
    // call EC_GROUP_set_asn1_flag(OPENSSL_EC_NAMED_CURVE) any more.

  } catch (OpenABE_ERROR& error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABEContextPKSIG::keygen(const std::string& pkID, const std::string& skID) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  EVP_PKEY_CTX* ctx = nullptr;
  EVP_PKEY* pkey = nullptr;
  shared_ptr<OpenABEPKey> pubKey = nullptr, privKey = nullptr;

  try {
    ASSERT(!this->curveName.empty(), OpenABE_ERROR_KEYGEN_FAILED);

    // Create a key-generation context for EC keys
    ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) {
      throw OpenABE_ERROR_KEYGEN_FAILED;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
      throw OpenABE_ERROR_KEYGEN_FAILED;
    }

    // Set the named curve
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 const_cast<char*>(this->curveName.c_str()), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
      throw OpenABE_ERROR_INVALID_GROUP_PARAMS;
    }

    // Generate the key pair (private + public)
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
      throw OpenABE_ERROR_KEYGEN_FAILED;
    }

    // Split into public-only and private key wrappers.
    // OpenABEPKey(EVP_PKEY*, false) extracts the public portion only.
    // OpenABEPKey(EVP_PKEY*, true)  duplicates the full key pair.
    pubKey.reset(new OpenABEPKey(pkey, false));
    privKey.reset(new OpenABEPKey(pkey, true));

    // Add the keys to the keystore
    this->getKeystore()->addKey(pkID, pubKey, KEY_TYPE_PUBLIC);
    this->getKeystore()->addKey(skID, privKey, KEY_TYPE_SECRET);

  } catch (OpenABE_ERROR& error) {
    result = error;
  }

  if (ctx)
    EVP_PKEY_CTX_free(ctx);
  if (pkey)
    EVP_PKEY_free(pkey);

  return result;
}

OpenABE_ERROR OpenABEContextPKSIG::sign(OpenABEPKey* privKey, OpenABEByteString* message,
                                        OpenABEByteString* signature) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  EVP_MD_CTX* md = nullptr;
  string error_msg = "";
  size_t siglen = 0;
  uint8_t* sig = nullptr;

  ASSERT_NOTNULL(privKey);
  ASSERT_NOTNULL(message);
  ASSERT_NOTNULL(signature);

  md = EVP_MD_CTX_create();
  if (!md) {
    error_msg = "EVP_MD_CTX_create";
    goto out;
  }

  if (EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, privKey->getPkey()) != 1) {
    error_msg = "EVP_DigestSignInit";
    goto out;
  }

  if (EVP_DigestSignUpdate(md, message->getInternalPtr(), message->size()) != 1) {
    error_msg = "EVP_DigestSignUpdate";
    goto out;
  }

  if (EVP_DigestSignFinal(md, NULL, &siglen) != 1) {
    error_msg = "EVP_DigestSignFinal(determine siglen)";
    goto out;
  }

  sig = (uint8_t*)OPENSSL_malloc((unsigned int)siglen);
  if (sig == nullptr) {
    error_msg = "OPENSSL_malloc failed in OpenABEContextPKSIG::sign";
    goto out;
  }

  if (EVP_DigestSignFinal(md, sig, &siglen) != 1) {
    error_msg = "EVP_DigestSignFinal(output sig)";
    goto out;
  }

  signature->clear();
  signature->appendArray(sig, siglen);

out:
  if (md) {
    EVP_MD_CTX_destroy(md);
  }

  if (error_msg != "") {
    OpenABE_LOG(error_msg);
    result = OpenABE_ERROR_SIGNATURE_FAILED;
  }

  if (sig != NULL) {
    OPENSSL_cleanse((char*)sig, siglen);
    OPENSSL_free(sig);
  }
  return result;
}

OpenABE_ERROR OpenABEContextPKSIG::verify(OpenABEPKey* pubKey, OpenABEByteString* message,
                                          OpenABEByteString* signature) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  EVP_MD_CTX* md = NULL;
  string error_msg = "";
  bool answer;

  ASSERT_NOTNULL(pubKey);
  ASSERT_NOTNULL(message);
  ASSERT_NOTNULL(signature);

  md = EVP_MD_CTX_create();
  if (!md) {
    error_msg = "EVP_MD_CTX_create";
    goto out;
  }

  if (EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, pubKey->getPkey()) != 1) {
    error_msg = "EVP_DigestVerifyInit";
    goto out;
  }

  if (EVP_DigestVerifyUpdate(md, message->getInternalPtr(), message->size()) != 1) {
    error_msg = "EVP_DigestVerifyUpdate";
    goto out;
  }

  answer = (EVP_DigestVerifyFinal(md, (unsigned char*)signature->getInternalPtr(),
                                  signature->size()) == 1);
  if (!answer) {
    error_msg = "EVP_DigestVerifyFinal failed";
    goto out;
  }

out:
  if (md) {
    EVP_MD_CTX_destroy(md);
  }

  if (error_msg != "") {
    OpenABE_LOG(error_msg);
    result = OpenABE_ERROR_VERIFICATION_FAILED;
  }

  return result;
}

bool OpenABEContextPKSIG::validatePkey(EVP_PKEY* pkey, bool expectPrivate) {
  if (!pkey) {
    return false;
  }

  // Verify this is an EC key
  if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC) {
    return false;
  }

  // Check whether the key carries a private component
  BIGNUM* priv = nullptr;
  bool hasPrivate =
      (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) == 1 && priv != nullptr);
  if (priv) {
    BN_free(priv);
  }

  return hasPrivate == expectPrivate;
}

bool OpenABEContextPKSIG::validatePublicKey(const shared_ptr<OpenABEPKey>& key) {
  ASSERT_NOTNULL(key);
  return this->validatePkey(key->getPkey(), false);
}

bool OpenABEContextPKSIG::validatePrivateKey(const std::shared_ptr<OpenABEPKey>& key) {
  ASSERT_NOTNULL(key);
  return this->validatePkey(key->getPkey(), true);
}

/********************************************************************************
 * Implementation of the OpenABEContextSchemePKSIG class
 ********************************************************************************/

OpenABEContextSchemePKSIG::OpenABEContextSchemePKSIG(unique_ptr<OpenABEContextPKSIG> pksig)
    : ZObject() {
  m_PKSIG = move(pksig);
}

OpenABEContextSchemePKSIG::~OpenABEContextSchemePKSIG() {}

OpenABE_ERROR OpenABEContextSchemePKSIG::exportKey(const string& keyID,
                                                   OpenABEByteString& keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    shared_ptr<OpenABEKey> key = this->m_PKSIG->getKeystore()->getKey(keyID);
    if (key == nullptr) {
      throw OpenABE_ERROR_INVALID_INPUT;
    }

    shared_ptr<OpenABEPKey> pkey = static_pointer_cast<OpenABEPKey>(key);
    ASSERT_NOTNULL(pkey);
    pkey->exportKeyToBytes(keyBlob);
  } catch (OpenABE_ERROR& error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABEContextSchemePKSIG::loadPrivateKey(const std::string& keyID,
                                                        OpenABEByteString& keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEPKey> SK = nullptr;
  bool isPrivate = true;

  try {
    SK.reset(new OpenABEPKey(isPrivate));
    SK->loadKeyFromBytes(keyBlob);

    if (this->m_PKSIG->validatePrivateKey(SK)) {
      this->m_PKSIG->getKeystore()->addKey(keyID, SK, KEY_TYPE_SECRET);
    } else {
      throw OpenABE_ERROR_INVALID_PARAMS;
    }

  } catch (OpenABE_ERROR& error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABEContextSchemePKSIG::loadPublicKey(const std::string& keyID,
                                                       OpenABEByteString& keyBlob) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEPKey> PK = nullptr;
  bool isPrivate = false;

  try {
    PK.reset(new OpenABEPKey(isPrivate));
    PK->loadKeyFromBytes(keyBlob);

    if (this->m_PKSIG->validatePublicKey(PK)) {
      this->m_PKSIG->getKeystore()->addKey(keyID, PK, KEY_TYPE_PUBLIC);
    } else {
      throw OpenABE_ERROR_INVALID_PARAMS;
    }

  } catch (OpenABE_ERROR& error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABEContextSchemePKSIG::deleteKey(const string& keyID) {
  return this->m_PKSIG->getKeystore()->deleteKey(keyID);
}

OpenABE_ERROR OpenABEContextSchemePKSIG::generateParams(const std::string groupParams) {
  return this->m_PKSIG->generateParams(groupParams);
}

OpenABE_ERROR OpenABEContextSchemePKSIG::keygen(const std::string& pkID, const std::string& skID) {
  return this->m_PKSIG->keygen(pkID, skID);
}

OpenABE_ERROR OpenABEContextSchemePKSIG::sign(const std::string& skID, OpenABEByteString* message,
                                              OpenABEByteString* signature) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEPKey> SK = nullptr;

  try {
    ASSERT_NOTNULL(message);
    ASSERT_NOTNULL(signature);

    SK = static_pointer_cast<OpenABEPKey>(this->m_PKSIG->getKeystore()->getSecretKey(skID));
    ASSERT_NOTNULL(SK);

    result = this->m_PKSIG->sign(SK.get(), message, signature);
    ASSERT(result == OpenABE_NOERROR, result);

  } catch (OpenABE_ERROR& error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABEContextSchemePKSIG::verify(const std::string& pkID, OpenABEByteString* message,
                                                OpenABEByteString* signature) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  shared_ptr<OpenABEPKey> PK = nullptr;

  try {
    ASSERT_NOTNULL(message);
    ASSERT_NOTNULL(signature);

    PK = static_pointer_cast<OpenABEPKey>(this->m_PKSIG->getKeystore()->getPublicKey(pkID));
    ASSERT_NOTNULL(PK);

    result = this->m_PKSIG->verify(PK.get(), message, signature);

  } catch (OpenABE_ERROR& error) {
    result = error;
  }

  return result;
}

} // namespace oabe