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
/// \file   zsymcrypto.cpp
///
/// \brief  Thin wrappers for symmetric key scheme contexts.
///
/// \author Alan Dunn and J. Ayo Akinyele
///

#include <sstream>
#include <stdexcept>
#include <cassert>
#include <openabe/zsymcrypto.h>

using namespace std;

namespace oabe {

namespace crypto {

/********************************************************************************
 * Implementation of the OpenABESymKeyAuthEnc class
 ********************************************************************************/

void OpenABEComputeHKDF(OpenABEByteString& key, OpenABEByteString& salt,
                        OpenABEByteString& info, size_t key_len, OpenABEByteString& output_key) {
  EVP_PKEY_CTX *kctx = NULL;
  string error_msg = "";
  // check if key is at least a certain size > 0, < 1024
  size_t out_len = key_len;
  uint8_t out_key[out_len+1];
  const EVP_MD *md = EVP_sha256();

  // allocates public key algorithm context using alg specified by id
  kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

  if (EVP_PKEY_derive_init(kctx) <= 0) {
	error_msg = "EVP_PKEY_derive_init";
	goto out;
  }

  if (EVP_PKEY_CTX_set_hkdf_md(kctx, md) <= 0) {
    error_msg = "EVP_PKEY_CTX_set_hkdf_md";
    goto out;
  }

  if (salt.size() > 0) {
	  if (EVP_PKEY_CTX_set1_hkdf_salt(kctx, salt.getInternalPtr(), salt.size()) <= 0) {
		error_msg = "EVP_PKEY_CTX_set1_salt";
		goto out;
	  }
  }

  if (EVP_PKEY_CTX_set1_hkdf_key(kctx, key.getInternalPtr(), key.size()) <= 0) {
	error_msg = "EVP_PKEY_CTX_set1_key";
	goto out;
  }

  if (info.size() > 0) {
	  if (EVP_PKEY_CTX_add1_hkdf_info(kctx, info.getInternalPtr(), info.size()) <= 0) {
		error_msg = "EVP_PKEY_CTX_add1_hkdf_info";
		goto out;
	  }
  }

  if (EVP_PKEY_derive(kctx, out_key, &out_len) <= 0) {
	error_msg = "EVP_PKEY_derive";
	goto out;
  }

  output_key.clear();
  output_key.appendArray(out_key, out_len);
out:
  // if kctx is NULL, nothing is done.
  EVP_PKEY_CTX_free(kctx);
  if (error_msg != "") {
    throw oabe::CryptoException(error_msg);
  }
}

void generateSymmetricKey(std::string& key, uint32_t keyLen)
{
    OpenABEByteString key_buf;
    OpenABERNG rng;
    rng.getRandomBytes(&key_buf, (int) keyLen);
    key = key_buf.toString();
}

// For debug purposes only!!
const string printAsHex(const string& bin_buf)
{
    OpenABEByteString buf;
    buf += bin_buf;
    return buf.toLowerHex();
}

OpenABESymKeyAuthEnc::OpenABESymKeyAuthEnc(int securitylevel, const string& zkey): ZObject()
{
    if(securitylevel == DEFAULT_AES_SEC_LEVEL) {
        this->cipher = (EVP_CIPHER *) EVP_aes_256_gcm();
        // cout << "cipher_block_size: " << EVP_CIPHER_block_size(this->cipher) << endl;
    }
    this->iv_len = AES_BLOCK_SIZE;
    this->aad_set = false;
    this->key = zkey;
}

OpenABESymKeyAuthEnc::OpenABESymKeyAuthEnc(int securitylevel, OpenABEByteString& zkey): ZObject()
{
    if(securitylevel == DEFAULT_AES_SEC_LEVEL) {
        this->cipher = (EVP_CIPHER *) EVP_aes_256_gcm();
        // cout << "cipher_block_size: " << EVP_CIPHER_block_size(this->cipher) << endl;
    }
    this->iv_len = AES_BLOCK_SIZE;
    this->aad_set = false;
    this->key = zkey;
}


OpenABESymKeyAuthEnc::~OpenABESymKeyAuthEnc()
{
    if (this->aad_set) {
        this->aad.zeroize();
    }
}

void
OpenABESymKeyAuthEnc::chooseRandomIV()
{
    RAND_bytes(this->iv, AES_BLOCK_SIZE);
}

void
OpenABESymKeyAuthEnc::setAddAuthData(OpenABEByteString &aad)
{
    if(aad.size() == 0) {
        // fill AAD buffer with 0's
        this->aad.fillBuffer(0, AES_BLOCK_SIZE);
    }
    else {
        // copy 'aad'
        this->aad = aad;
    }
    this->aad_set = true;
}

void
OpenABESymKeyAuthEnc::setAddAuthData(uint8_t *aad, uint32_t aad_len)
{
    this->aad.clear();
    if(aad) {
        this->aad.appendArray(aad, aad_len);
    } else {
        // fill AAD buffer with 0's
        this->aad.fillBuffer(0, AES_BLOCK_SIZE);
    }
    this->aad_set = true;
}


OpenABE_ERROR
OpenABESymKeyAuthEnc::encrypt(const string& plaintext, OpenABEByteString *iv, OpenABEByteString *ciphertext, OpenABEByteString *tag)
{
    OpenABE_ERROR result = OpenABE_NOERROR;
    uint8_t *ct = nullptr;

    try {
        ASSERT_NOTNULL(iv);
        ASSERT_NOTNULL(ciphertext);
        ASSERT_NOTNULL(tag);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        OpenABEByteString ivObj, ctObj, tagObj;
        uint8_t *pt_ptr = (uint8_t *) plaintext.c_str();
        int len = 0, ctlen, pt_len = plaintext.size();
        if(pt_len < AES_BLOCK_SIZE)
            /* add block size to the len */
            len += AES_BLOCK_SIZE;
        else
            /* add pt_len + block size to len */
            len += pt_len;
        // allocate the temp output ciphertext buffer
        // uint8_t ct[len+1];
        ct = (uint8_t*) malloc(len+1);
        MALLOC_CHECK_OUT_OF_MEMORY(ct);
        memset(ct, 0, len+1);

        // cout << "Plaintext:\n";
        // BIO_dump_fp(stdout, (const char *) &((*plaintext)[0]), plaintext->size());
        // cout << "Enc Key:\n";
        // BIO_dump_fp(stdout, (const char *) this->key.getInternalPtr(), this->key.size());

        /* set cipher type and mode */
        EVP_EncryptInit_ex(ctx, this->cipher, NULL, NULL, NULL);
        /* set the IV length as 128-bits */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_BLOCK_SIZE, NULL);
        /* initialize key and IV */

        chooseRandomIV();
        EVP_EncryptInit_ex(ctx, NULL, NULL, this->key.getInternalPtr(), this->iv);
        iv->clear();
        iv->appendArray(this->iv, this->iv_len);

        /* specify the additional authentication data (aad) */
        if (this->aad_set) {
            EVP_EncryptUpdate(ctx, NULL, &ctlen, this->aad.getInternalPtr(), this->aad.size());
        }

        /* encrypt plaintext */
        EVP_EncryptUpdate(ctx, ct, &ctlen, pt_ptr, pt_len);

        // cout << "Ciphertext:\n";
        // BIO_dump_fp(stdout, (const char *) ct, ctlen);
        ciphertext->clear();
        ciphertext->appendArray(ct, ctlen);

        /* finalize: computes authentication tag*/
        EVP_EncryptFinal_ex(ctx, ct, &len);
        // For AES-GCM, the 'len' should be '0' because there is no extra bytes used for padding.
        ASSERT(len == 0, OpenABE_ERROR_UNEXPECTED_EXTRA_BYTES);

        /* retrieve the tag */
        int tag_len = AES_BLOCK_SIZE;
        uint8_t tag_buf[tag_len+1];
        memset(tag_buf, 0, tag_len+1);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag_buf);

        // cout << "Tag:\n";
        // BIO_dump_fp(stdout, (const char *) tag_buf, tag_len);
        tag->clear();
        tag->appendArray(tag_buf, tag_len);

        EVP_CIPHER_CTX_free(ctx);
    } catch(OpenABE_ERROR& e) {
        result = e;
    }
    if (ct)
        free(ct);
    return result;
}

bool
OpenABESymKeyAuthEnc::decrypt(string& plaintext, OpenABEByteString* iv, OpenABEByteString* ciphertext, OpenABEByteString* tag)
{
    ASSERT_NOTNULL(iv);
    ASSERT_NOTNULL(ciphertext);
    ASSERT_NOTNULL(tag);

    if(ciphertext->size() == 0) {
        /* ciphertext has to be greater than 0 */
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t *pt = nullptr;
    OpenABEByteString pt_buf;

    int pt_len, retValue;
    uint8_t *ct_ptr = ciphertext->getInternalPtr();
    int ct_len = ciphertext->size();
    // cout << "Dec Ciphertext:\n";
    // BIO_dump_fp(stdout, (const char *) ct_ptr, ct_len);

    uint8_t *tag_ptr =  tag->getInternalPtr();
    int tag_len = tag->size();
    ASSERT(tag_len == AES_BLOCK_SIZE, OpenABE_ERROR_INVALID_TAG_LENGTH);
    // cout << "Dec Tag:\n";
    // BIO_dump_fp(stdout, (const char *) tag_ptr, tag_len);

    /* set cipher type and mode */
    EVP_DecryptInit_ex(ctx, this->cipher, NULL, NULL, NULL);
    /* set the IV length as 128-bits */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv->size(), NULL);
    /* specify key and iv */
    // cout << "Dec Key:\n";
    // BIO_dump_fp(stdout, (const char *) this->key.getInternalPtr(), this->key.size());
    EVP_DecryptInit_ex(ctx, NULL, NULL, this->key.getInternalPtr(), iv->getInternalPtr());

    // OpenSSL says tag must be set *before* any EVP_DecryptUpdate call.
    // This is a restriction for OpenSSL v1.0.1c and prior versions but also works
    // thesame for later versions. To avoid OpenSSL version checks, we set the tag
    // here which should work across all versions.
    /* set the tag expected value */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag_ptr);

    /* specify additional authentication data */
    if(this->aad_set) {
        EVP_DecryptUpdate(ctx, NULL, &pt_len, this->aad.getInternalPtr(), this->aad.size());
    }

    // uint8_t pt[ct_len+1];
    pt = (uint8_t*) malloc(ct_len+1);
    MALLOC_CHECK_OUT_OF_MEMORY(pt);
    memset(pt, 0, ct_len+1);
    /* decrypt and store plaintext in pt buffer */
    EVP_DecryptUpdate(ctx, pt, &pt_len, ct_ptr, ct_len);
    pt_buf.appendArray(pt, (uint32_t) pt_len);

    // cout << "Plaintext:\n";
    // BIO_dump_fp(stdout, (const char *) pt, pt_len);

    /* finalize decryption */
    retValue = EVP_DecryptFinal_ex(ctx, pt, &pt_len);
    if (pt) {
        free(pt);
    }
    // printf("Tag Verify %s\n", retValue > 0 ? "Successful!" : "Failed!");

    EVP_CIPHER_CTX_free(ctx);
    if(retValue > 0) {
        /* tag verification successful */
        plaintext = pt_buf.toString();
        pt_buf.zeroize();
        return true;
    }
    else {
        /* authentication failure */
        return false;
    }
}

/********************************************************************************
 * Implementation of the OpenABESymKeyHandleImpl class
 ********************************************************************************/

OpenABESymKeyHandleImpl::OpenABESymKeyHandleImpl(const string& keyBytes, bool apply_b64_encode) {
    try {
        if (keyBytes.size() != DEFAULT_SYM_KEY_BYTES) {
            throw OpenABE_ERROR_INVALID_LENGTH;
        }

        security_level_ = DEFAULT_AES_SEC_LEVEL;
    } catch (OpenABE_ERROR& error) {
        string msg = OpenABE_errorToString(error);
        throw runtime_error(msg);
    }

    key_ = keyBytes;
    b64_encode_ = apply_b64_encode;
}

OpenABESymKeyHandleImpl::OpenABESymKeyHandleImpl(OpenABEByteString& keyBytes,
		                                 OpenABEByteString& authData, bool apply_b64_encode) {
    try {
        key_ = keyBytes.toString();
        if (key_.size() != DEFAULT_SYM_KEY_BYTES) {
            throw OpenABE_ERROR_INVALID_LENGTH;
        }

        security_level_ = DEFAULT_AES_SEC_LEVEL;
    } catch (OpenABE_ERROR& error) {
        string msg = OpenABE_errorToString(error);
        throw runtime_error(msg);
    }

    authData_ = authData;
    b64_encode_ = apply_b64_encode;
}


OpenABESymKeyHandleImpl::~OpenABESymKeyHandleImpl() {
    key_.clear();
    authData_.clear();
}

void OpenABESymKeyHandleImpl::encrypt(string& ciphertext, const string& plaintext)
{
    unique_ptr<OpenABESymKeyAuthEnc> symkeyContext_(new OpenABESymKeyAuthEnc(security_level_, key_));
    try {
        OpenABEByteString zciphertext, ziv, zct, ztag;
        // set the additional auth data (if set)
        if (authData_.size() > 0) {
        	symkeyContext_->setAddAuthData(authData_);
        } else {
        	symkeyContext_->setAddAuthData(NULL, 0);
        }
        // now we can encrypt with sym key
        if (symkeyContext_->encrypt(plaintext, &ziv, &zct, &ztag) != OpenABE_NOERROR) {
            throw runtime_error("Encryption failed");
        }

        // serialize all three ziv, zciphertext and ztag
        // cout << "<=== ENCRYPT ===>" << endl;
        // cout << "iv: " << ziv.toLowerHex() << endl;
        // cout << "ct: " << zct.toLowerHex() << endl;
        // cout << "tg: " << ztag.toLowerHex() << endl;
        // cout << "<=== ENCRYPT ===>" << endl;

        zciphertext.smartPack(ziv);
        zciphertext.smartPack(zct);
        zciphertext.smartPack(ztag);
        string s = zciphertext.toString();
        if (b64_encode_) {
            // output base64 encoded version
            ciphertext = Base64Encode((const unsigned char *)s.c_str(), s.size());
        } else {
            // output binary (caller handles encoding format)
            ciphertext = s;
        }
    } catch (OpenABE_ERROR& error) {
        string msg = OpenABE_errorToString(error);
        throw runtime_error(msg);
    }
}

void OpenABESymKeyHandleImpl::decrypt(string& plaintext, const string& ciphertext)
{
    unique_ptr<OpenABESymKeyAuthEnc> symkeyContext_(new OpenABESymKeyAuthEnc(security_level_, key_));
    try {
        size_t index = 0;
        OpenABEByteString zciphertext;
        if (b64_encode_) {
            zciphertext += Base64Decode(ciphertext);
        } else {
            zciphertext += ciphertext;
        }
        OpenABEByteString ziv, zct, ztag;
        ziv = zciphertext.smartUnpack(&index);
        zct = zciphertext.smartUnpack(&index);
        ztag = zciphertext.smartUnpack(&index);

        // set the additional auth data (if set)
        if (authData_.size() > 0) {
           symkeyContext_->setAddAuthData(authData_);
        } else {
           symkeyContext_->setAddAuthData(NULL, 0);
        }
        bool dec_status = symkeyContext_->decrypt(plaintext, &ziv, &zct, &ztag);
        if (!dec_status) {
            throw runtime_error("Decryption failed");
        }
    } catch (OpenABE_ERROR& error) {
        string msg = OpenABE_errorToString(error);
        throw runtime_error(msg);
    }
}

void
OpenABESymKeyHandleImpl::exportRawKey(string& key) {
    key = this->key_;
}

void
OpenABESymKeyHandleImpl::exportKey(string& key) {
    size_t key_len = this->key_.size();
	OpenABEByteString secret_key, salt, info, output_key;
	secret_key += this->key_;
	// info: export key is the label
	info += "export key";
	OpenABEComputeHKDF(secret_key, salt, info, key_len, output_key);
	key = output_key.toString();
}

}}
