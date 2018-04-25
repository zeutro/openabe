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
/// \file   zcontextpksig.cpp
///
/// \brief  Implementation for OpenABE context PKSIG schemes.
///
/// \author J. Ayo Akinyele
///
///   

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEContextPKSIG class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEContextPKSIG base class.
 *
 */
OpenABEContextPKSIG::OpenABEContextPKSIG(): OpenABEContext() {
    this->group = nullptr;
}

/*!
 * Destructor for the OpenABEContextPKSIG base class.
 *
 */
OpenABEContextPKSIG::~OpenABEContextPKSIG() {
    if(this->group != nullptr) {
        EC_GROUP_free(this->group);
    }
}

OpenABE_ERROR
OpenABEContextPKSIG::initializeCurve(const std::string groupParams) {
    try {
        if(this->group == nullptr) {
            generateECCurveParameters(&this->group, groupParams);
            ASSERT_NOTNULL(this->group);
        }
    } catch(OpenABE_ERROR& error) {
        return error;
    }

    return OpenABE_NOERROR;
}

OpenABE_ERROR
OpenABEContextPKSIG::generateParams(const std::string groupParams) {
    OpenABE_ERROR result  = OpenABE_NOERROR;

    try {
        // initialize the group (if not already)
        this->initializeCurve(groupParams);

        // ***Important***
        // The ASN1 flag causes OpenSSL to maintain curve names in the
        // keys it saves.  This is necessary for TLS to work properly
        // (without enabling generic EC group support in TLS options,
        // which maybe you can do?)
        EC_GROUP_set_asn1_flag(this->group, OPENSSL_EC_NAMED_CURVE);

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextPKSIG::keygen(const std::string &pkID, const std::string &skID) {
    OpenABE_ERROR result   = OpenABE_NOERROR;
    EC_KEY *ec_key     = nullptr;
    shared_ptr<OpenABEPKey> pubKey = nullptr, privKey = nullptr;

    try {
        ASSERT_NOTNULL(this->group);

        ec_key = EC_KEY_new();
        ASSERT_NOTNULL(ec_key);

        if (EC_KEY_set_group(ec_key, this->group) == 0) {
            throw OpenABE_ERROR_INVALID_GROUP_PARAMS;
        }

        // generate ECDSA keys and store inside the ec_key object
        if (!EC_KEY_generate_key(ec_key)) {
            throw OpenABE_ERROR_KEYGEN_FAILED;
        }

        // now split the EC_KEY into public and private key structures
        // and instantiate the OpenABEPKey objects
        pubKey.reset(new OpenABEPKey(ec_key, false, this->group));
        privKey.reset(new OpenABEPKey(ec_key, true));

        // add the keys to the keystore
        this->getKeystore()->addKey(pkID, pubKey,  KEY_TYPE_PUBLIC);
        this->getKeystore()->addKey(skID, privKey, KEY_TYPE_SECRET);

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}


OpenABE_ERROR
OpenABEContextPKSIG::sign(OpenABEPKey *privKey, OpenABEByteString *message, OpenABEByteString *signature) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    EVP_MD_CTX* md = nullptr;
    string error_msg = "";
    size_t siglen = 0;
    uint8_t *sig = nullptr;

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

    // using openssl malloc instead of OpenABEByteString->fillBuffer
    // to avoid trailing zero bytes. Trailing zero bytes
    // invalidates ECDSA_verify DER encoding/decoding test.
    // NOTE: this was exposed by recent improvements
    // in openssl-1.0.1l
    sig = (uint8_t *)OPENSSL_malloc((unsigned int)siglen);
    if (sig == nullptr) {
        error_msg = "OPENSSL_malloc failed in OpenABEContextPKSIG::sign";
        goto out;
    }
    // Extract the signature
    if (EVP_DigestSignFinal(md, sig, &siglen) != 1) {
        error_msg = "EVP_DigestSignFinal(output sig)";
        goto out;
    }
    // return sig as a OpenABEByteString
    signature->clear();
    signature->appendArray(sig, siglen);
out:
    if (md) {
        EVP_MD_CTX_destroy(md);
    }

    if(error_msg != "") {
        OpenABE_LOG(error_msg);
        result = OpenABE_ERROR_SIGNATURE_FAILED;
    }

    if (sig != NULL) {
        OPENSSL_cleanse((char *)sig, siglen);
        OPENSSL_free(sig);
    }
    return result;
}

OpenABE_ERROR
OpenABEContextPKSIG::verify(OpenABEPKey *pubKey, OpenABEByteString *message, OpenABEByteString *signature) {
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

    answer = (EVP_DigestVerifyFinal(md, (unsigned char*)signature->getInternalPtr(), signature->size()) == 1);
    if(!answer) {
        error_msg = "EVP_DigestVerifyFinal failed";
        goto out;
    }

out:
    if (md) {
        EVP_MD_CTX_destroy(md);
    }

    if(error_msg != "") {
        OpenABE_LOG(error_msg);
        result = OpenABE_ERROR_VERIFICATION_FAILED;
    }

    return result;
}

bool
OpenABEContextPKSIG::validatePkey(EVP_PKEY* pkey, bool expectPrivate) {
    EC_KEY* eckey;
    const EC_GROUP* group;
    bool result = false;
    bool hasPrivate;

    eckey = EVP_PKEY_get1_EC_KEY(pkey);
    if (!eckey) {
        // Wrong key type
        goto out;
    }
    group = EC_KEY_get0_group(eckey);
    if (!group) {
        // Shouldn't happen
        goto out;
    }
    // Check public versus private key
    hasPrivate = (EC_KEY_get0_private_key(eckey) != NULL);
    if (hasPrivate != expectPrivate) {
        goto out;
    }

    // Success
    result = true;

    out:
    if (eckey) {
        EC_KEY_free(eckey);
    }

    return result;
}

bool
OpenABEContextPKSIG::validatePublicKey(const shared_ptr<OpenABEPKey>& key) {
    ASSERT_NOTNULL(key);
    return this->validatePkey(key->getPkey(), false);
}


bool
OpenABEContextPKSIG::validatePrivateKey(const std::shared_ptr<OpenABEPKey>& key) {
    ASSERT_NOTNULL(key);
//	return this->validatePkey(key->getPkey(), true);
    return true;
}


/********************************************************************************
 * Implementation of the OpenABEContextSchemePKSIG class
 ********************************************************************************/

OpenABEContextSchemePKSIG::OpenABEContextSchemePKSIG(unique_ptr<OpenABEContextPKSIG> pksig): ZObject() {
    m_PKSIG = move(pksig);
}

OpenABEContextSchemePKSIG::~OpenABEContextSchemePKSIG() {
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::exportKey(const string &keyID, OpenABEByteString &keyBlob) {
    OpenABE_ERROR result = OpenABE_NOERROR;

    try {
        // attempt to export the given keyID to a temp keyBlob output buffer (without a header)
        shared_ptr<OpenABEKey> key = this->m_PKSIG->getKeystore()->getKey(keyID);
        if(key == nullptr) {
            throw OpenABE_ERROR_INVALID_INPUT;
        }

        // convert to pkey
        shared_ptr<OpenABEPKey> pkey = static_pointer_cast<OpenABEPKey>(key);
        ASSERT_NOTNULL(pkey);
        // export key to bytes
        pkey->exportKeyToBytes(keyBlob);
    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::loadPrivateKey(const std::string &keyID, OpenABEByteString &keyBlob) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    shared_ptr<OpenABEPKey> SK = nullptr;
    bool isPrivate = true;

    try {
        // now we can deserialize the key directly
        SK.reset(new OpenABEPKey(isPrivate));
        SK->loadKeyFromBytes(keyBlob);

        if(this->m_PKSIG->validatePrivateKey(SK)) {
            // if validation successful, then add to the keystore
            this->m_PKSIG->getKeystore()->addKey(keyID, SK, KEY_TYPE_SECRET);
        }
        else {
            throw OpenABE_ERROR_INVALID_PARAMS;
        }

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::loadPublicKey(const std::string &keyID, OpenABEByteString &keyBlob) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    shared_ptr<OpenABEPKey> PK = nullptr;
    bool isPrivate = false;

    try {
        // now we can deserialize the key directly
        PK.reset(new OpenABEPKey(isPrivate));
        PK->loadKeyFromBytes(keyBlob);

        if(this->m_PKSIG->validatePublicKey(PK)) {
            // if validation successful, then add to the keystore
            this->m_PKSIG->getKeystore()->addKey(keyID, PK, KEY_TYPE_PUBLIC);
        }
        else {
            throw OpenABE_ERROR_INVALID_PARAMS;
        }

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::deleteKey(const string &keyID) {
    return this->m_PKSIG->getKeystore()->deleteKey(keyID);
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::generateParams(const std::string groupParams) {
    return this->m_PKSIG->generateParams(groupParams);
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::keygen(const std::string &pkID, const std::string &skID) {
    return this->m_PKSIG->keygen(pkID, skID);
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::sign(const std::string &skID, OpenABEByteString *message, OpenABEByteString *signature) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    shared_ptr<OpenABEPKey> SK = nullptr;

    try {
        ASSERT_NOTNULL(message);
        ASSERT_NOTNULL(signature);

        // load the secret key from the keystore
        SK = static_pointer_cast<OpenABEPKey>(this->m_PKSIG->getKeystore()->getSecretKey(skID));
        ASSERT_NOTNULL(SK);

        // sign the message with the key that was just loaded
        result = this->m_PKSIG->sign(SK.get(), message, signature);
        ASSERT(result == OpenABE_NOERROR, result);

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

OpenABE_ERROR
OpenABEContextSchemePKSIG::verify(const std::string &pkID, OpenABEByteString *message, OpenABEByteString *signature) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    shared_ptr<OpenABEPKey> PK = nullptr;

    try {
        ASSERT_NOTNULL(message);
        ASSERT_NOTNULL(signature);

        // load the public key from the keystore
        PK = static_pointer_cast<OpenABEPKey>(this->m_PKSIG->getKeystore()->getPublicKey(pkID));
        ASSERT_NOTNULL(PK);

        // verify the message and signature against a verification key
        result = this->m_PKSIG->verify(PK.get(), message, signature);

    } catch(OpenABE_ERROR& error) {
        result = error;
    }

    return result;
}

}
