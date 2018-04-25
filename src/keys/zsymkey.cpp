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
/// \file   zsymkey.cpp
///
/// \brief  Implementation for storing and manipulating
///         the symmetric enc OpenABE keys
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OpenABESYMKEY_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cmath>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABESymKey class
 ********************************************************************************/
namespace oabe {
/*!
 * Constructor for the OpenABESymKey class.
 *
 */
OpenABESymKey::OpenABESymKey() : OpenABEKey() {}

/*!
 * Destructor for the STKSymKey class.
 *
 */
OpenABESymKey::~OpenABESymKey() {
    // Zeroize contents of key buffer
    this->m_keyData.zeroize();
}

OpenABE_ERROR OpenABESymKey::loadKeyFromBytes(OpenABEByteString &input) {
  if (input.size() == 0) {
    return OpenABE_ERROR_INVALID_LENGTH;
  }
  this->m_keyData = input;
  return OpenABE_NOERROR;
}

OpenABE_ERROR OpenABESymKey::exportKeyToBytes(OpenABEByteString &output) {
  output = this->m_keyData;
  return OpenABE_NOERROR;
}

/*!
 * Debugging function. Outputs a symmetric key in a human-readable
 * string format. Don't use this in production code!
 *
 * @return  Key as a formatted string.
 */
string OpenABESymKey::toString() { return this->m_keyData.toHex(); }

/*!
 * Hashes a group element into a symmetric key.
 *
 * @throw  An exception if there's an error.
 */

bool OpenABESymKey::hashToSymmetricKey(GT &input, uint32_t keyLen,
                                   OpenABEHashFunctionType hashType) {
  this->m_keyData.clear();
  // Hash the element into the key
  return OpenABEUtilsHashToString(input, keyLen, this->m_keyData, hashType);
}

bool OpenABESymKey::generateSymmetricKey(uint32_t keyLen) {
  // Clear the original key
  OpenABERNG rng;
  rng.getRandomBytes(&this->m_keyData, (int)keyLen);
  return true;
}

void OpenABESymKey::setSymmetricKey(OpenABEByteString &key) {
  this->m_keyData.clear();
  this->m_keyData = key;
}

bool operator==(const OpenABESymKey &lhs, const OpenABESymKey &rhs) {
  return (lhs.m_keyData.size() == rhs.m_keyData.size() &&
          lhs.m_keyData == lhs.m_keyData);
}

/********************************************************************************
 * Implementation of the OpenABESymKeyEnc class
 ********************************************************************************/

OpenABESymKeyEnc::OpenABESymKeyEnc(string key) : ZObject() {
  this->seclevel = DEFAULT_SECURITY_LEVEL;
  this->keyStr = key;
  this->key = (AES_KEY *)malloc(sizeof(AES_KEY));
  MALLOC_CHECK_OUT_OF_MEMORY(this->key);
  memset(this->iv, 0, AES_BLOCK_SIZE + 1);
  this->iv_set = false;
  this->status = false;
}

OpenABESymKeyEnc::OpenABESymKeyEnc(int securitylevel, string key) : ZObject() {
  this->seclevel = securitylevel;
  this->keyStr = key;
  this->key = (AES_KEY *)malloc(sizeof(AES_KEY));
  MALLOC_CHECK_OUT_OF_MEMORY(this->key);
  memset(this->iv, 0, AES_BLOCK_SIZE + 1);
  this->iv_set = false;
  this->status = false;
}

OpenABESymKeyEnc::OpenABESymKeyEnc(int securitylevel, uint8_t *iv, string key)
    : ZObject() {
  /* copy iv and key into */
  this->seclevel = securitylevel;
  memset(this->iv, 0, AES_BLOCK_SIZE + 1);
  memcpy(this->iv, iv, AES_BLOCK_SIZE + 1);
  this->iv_set = true;
  this->keyStr = key;
  this->key = (AES_KEY *)malloc(sizeof(AES_KEY));
  MALLOC_CHECK_OUT_OF_MEMORY(this->key);
  this->status = false;
}

OpenABESymKeyEnc::~OpenABESymKeyEnc() { SAFE_FREE(this->key); }

void OpenABESymKeyEnc::chooseRandomIV() {
  if (!this->iv_set) {
    ASSERT_RNG(RAND_bytes(this->iv, AES_BLOCK_SIZE));
  }
}

// an 32-bit length field means we can encrypt 4GB files
string OpenABESymKeyEnc::encrypt(uint8_t *plaintext, uint32_t plaintext_len) {
  // select a new IV
  this->chooseRandomIV();
  // base-64 encode and serialize IV
  string iv_encoded = Base64Encode(this->iv, AES_BLOCK_SIZE);

  // instantiate AES_KEY
  AES_set_encrypt_key((uint8_t *)this->keyStr.c_str(), this->seclevel,
                      this->key);

  // compute ciphertext size and round to nearest block
  int ct_len =
      (int)ceil((plaintext_len + sizeof(uint32_t)) / (double)(AES_BLOCK_SIZE)) *
      AES_BLOCK_SIZE;
  uint8_t plaintext2[ct_len + 1];
  memset(plaintext2, 0, ct_len + 1);

  // big-endian
  plaintext2[3] = (plaintext_len & 0x000000FF);
  plaintext2[2] = (plaintext_len & 0x0000FF00) >> 8;
  plaintext2[1] = (plaintext_len & 0x00FF0000) >> 16;
  plaintext2[0] = (plaintext_len & 0xFF000000) >> 24;
  memcpy((uint8_t *)(plaintext2 + sizeof(uint32_t)), plaintext, plaintext_len);
  //	cout << "PT=> " << debug_print_as_hex(plaintext2, ct_len) << endl;

  // encrypt ciphertext using AES_CBC_128 (for now)
  uint8_t ct[ct_len + 1];
  memset(ct, 0, ct_len + 1);
  AES_cbc_encrypt(plaintext2, ct, ct_len, this->key, this->iv, AES_ENCRYPT);
  string ct_encoded = Base64Encode(ct, ct_len);

  // cout << "...AES Encrypt...\n";
  // cout << "IV=> " << iv_encoded << endl;
  // cout << "CT=> " << debug_print_as_hex(ct, ct_len) << endl;
  // cout << "...AES Encrypt...\n";

  return iv_encoded + ":" + ct_encoded;
}

string OpenABESymKeyEnc::decrypt(string ciphertext) {
  // deserialize ciphertext blob (split on ':')
  vector<string> list = split(ciphertext, ':');
  if (list.size() != 2) {
    status = false;
    return "";
  }
  string IV = Base64Decode(list[0]);
  if (IV.size() != AES_BLOCK_SIZE) {
    status = false;
    return "";
  }
  string ct = Base64Decode(list[1]);
  size_t ct_len = ct.size();

  if (!this->iv_set) {
    // if IV was not set in the constructor, use IV in ciphertext
    memset(this->iv, 0, AES_BLOCK_SIZE);
    memcpy(this->iv, IV.c_str(), AES_BLOCK_SIZE);
  }

  // cout << "...AES Decrypt...\n";
  // cout << "IV=> " << debug_print_as_hex(this->iv, AES_BLOCK_SIZE) << endl;
  // cout << "CT=> " << debug_print_as_hex((uint8_t*) ct.c_str(), ct_len) <<
  // endl;

  // instantiate AES_KEY
  AES_set_decrypt_key((uint8_t *)this->keyStr.c_str(), this->seclevel,
                      this->key);

  uint8_t plaintext[ct_len + 1];
  memset(plaintext, 0, ct_len + 1);
  AES_cbc_encrypt((uint8_t *)ct.c_str(), plaintext, ct_len, this->key, this->iv,
                  AES_DECRYPT);

  // cout << "PT=> " << debug_print_as_hex(plaintext, ct_len) << endl;
  // cout << "...AES Decrypt...\n";
  uint32_t len = 0;
  len |= (plaintext[0] << 24);
  len |= (plaintext[1] << 16);
  len |= (plaintext[2] << 8);
  len |= plaintext[3];

  if (len > ct_len) {
    status = false;
    return "ACCESS DENIED\n";
  }
  string plaintext2 = string((char *)(plaintext + sizeof(uint32_t)), len);
  status = true;
  return plaintext2;
}

/********************************************************************************
 * Implementation of the OpenABESymKeyAuthEncStream class
 ********************************************************************************/

OpenABESymKeyAuthEncStream::OpenABESymKeyAuthEncStream(
    int securitylevel, const std::shared_ptr<OpenABESymKey> &key)
    : ZObject() {
  if (securitylevel == DEFAULT_AES_SEC_LEVEL) {
    this->cipher = (EVP_CIPHER *)EVP_aes_256_gcm();
    // cout << "cipher_block_size: " << EVP_CIPHER_block_size(this->cipher) <<
    // endl;
  }
  this->key = key;
  this->aad_set = false;
  this->init_enc_set = false;
  this->init_dec_set = false;
  this->total_ct_len = -1;
  this->updateEncCount = -1;
  this->updateDecCount = -1;
  this->ctx = NULL;
}

OpenABESymKeyAuthEncStream::~OpenABESymKeyAuthEncStream() {
  if (this->ctx != NULL)
    EVP_CIPHER_CTX_free(this->ctx);
}

void OpenABESymKeyAuthEncStream::initAddAuthData(uint8_t *aad, uint32_t aad_len) {
  if (this->init_enc_set || this->init_dec_set) {
    if (aad == NULL) {
      // fill AAD buffer with 0's
      this->aad.fillBuffer(0, AES_BLOCK_SIZE);
    } else {
      this->aad.appendArray(aad, aad_len);
    }
    this->aad_set = true;
  }
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::setAddAuthData() {
  /* specify the additional authentication data (aad) */
  uint8_t *aad_ptr = this->aad.getInternalPtr();
  int aad_len = this->aad.size();
  int ct_len = 0;

  if (this->init_enc_set && this->aad_set) {
    EVP_EncryptUpdate(this->ctx, NULL, &ct_len, aad_ptr, aad_len);
    ASSERT(ct_len == aad_len, OpenABE_ERROR_INVALID_INPUT);
  } else if (this->init_dec_set && this->aad_set) {
    EVP_DecryptUpdate(this->ctx, NULL, &ct_len, aad_ptr, aad_len);
    ASSERT(ct_len == aad_len, OpenABE_ERROR_INVALID_INPUT);
  } else {
    return OpenABE_INVALID_INPUT_TYPE;
  }

  return OpenABE_NOERROR;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::encryptInit(OpenABEByteString *iv) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  try {
    if (!this->init_enc_set) {
      /* can't mix encryptInit AND decryptInit at the same time */
      ASSERT(!this->init_dec_set, OpenABE_ERROR_INVALID_INPUT);
      this->ctx = EVP_CIPHER_CTX_new();
      /* set cipher type and mode */
      EVP_EncryptInit_ex(this->ctx, this->cipher, NULL, NULL, NULL);
      /* set the IV length as 128-bits (or 16 bytes) */
      EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_GCM_SET_IVLEN, AES_BLOCK_SIZE,
                          NULL);
      /* initialize key and IV */
      OpenABERNG rng;
      rng.getRandomBytes(&this->the_iv, AES_BLOCK_SIZE);

      EVP_EncryptInit_ex(this->ctx, NULL, NULL, this->key->getInternalPtr(),
                         this->the_iv.getInternalPtr());
      /* save the generated IV */
      iv->clear();
      *iv += this->the_iv;
      /* initialize internal counters and state */
      this->total_ct_len = 0;
      this->updateEncCount = 0;
      this->init_enc_set = true;
    } else {
      throw OpenABE_ERROR_IN_USE_ALREADY;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::encryptUpdate(OpenABEByteString *plaintextBlock,
                                                OpenABEByteString *ciphertext) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  if (this->init_enc_set) {
    /* encrypt plaintext */
    uint8_t *pt_ptr = plaintextBlock->getInternalPtr();
    int pt_len = plaintextBlock->size();
    int ct_len = 0;
    /* make sure that the plaintext is at least 1 byte (since AES-GCM works on
     * non-aligned block sizes) */
    ASSERT(pt_len > 0, OpenABE_ERROR_INVALID_INPUT);

    /* perform encryption update on the given plaintext */
    uint8_t ct[pt_len + 1];
    memset(ct, 0, pt_len);
    EVP_EncryptUpdate(this->ctx, ct, &ct_len, pt_ptr, pt_len);
    /* make sure we are not writing more than we've allocated */
    ASSERT(pt_len == ct_len, OpenABE_ERROR_INVALID_INPUT);
    /* keep track of the total ciphertext length so far*/
    this->total_ct_len += ct_len;
    /* return back to user */
    ciphertext->appendArray(ct, ct_len);
    /* increment number of encrypt updates the user has performed */
    this->updateEncCount++;
  }

  return result;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::encryptFinalize(OpenABEByteString *ciphertext,
                                                  OpenABEByteString *tag) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  if (this->init_enc_set && this->updateEncCount > 0) {
    /* finalize: computes authentication tag*/
    uint8_t *ct_ptr = ciphertext->getInternalPtr();
    /* make sure 'ct' size is the same as our internal size counter */
    ASSERT(ciphertext->size() == this->total_ct_len, OpenABE_ERROR_INVALID_INPUT);
    /* now we can finalize encryption */
    EVP_EncryptFinal_ex(this->ctx, ct_ptr, (int *)&this->total_ct_len);
    // For AES-GCM, the 'len' should be '0' because there is no extra bytes used
    // for padding.
    ASSERT(this->total_ct_len == 0, OpenABE_ERROR_UNEXPECTED_EXTRA_BYTES);

    /* retrieve the tag */
    int tag_len = AES_BLOCK_SIZE;
    uint8_t tag_ptr[tag_len + 1];
    memset(tag_ptr, 0, tag_len + 1);
    EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag_ptr);
    //    cout << "Tag:\n";
    //    BIO_dump_fp(stdout, (const char *) tag, tag_len);
    tag->appendArray(tag_ptr, tag_len);

    // house keeping
    this->updateEncCount = 0;
    EVP_CIPHER_CTX_free(this->ctx);
    this->ctx = NULL;
    // clear some buffers
    this->the_iv.fillBuffer(0, this->the_iv.size());
    this->aad.fillBuffer(0, this->aad.size());
    this->aad_set = false;
    // reset state
    this->init_enc_set = false;
  }

  return result;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::decryptInit(OpenABEByteString *iv,
                                              OpenABEByteString *tag) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  try {
    if (!this->init_dec_set) {
      /* can't mix encryptInit AND decryptInit at the same time */
      ASSERT(!this->init_enc_set, OpenABE_ERROR_INVALID_INPUT);

      ASSERT_NOTNULL(iv);
      ASSERT_NOTNULL(tag);

      /* allocate cipher context */
      this->ctx = EVP_CIPHER_CTX_new();

      /* set cipher type and mode */
      EVP_DecryptInit_ex(this->ctx, this->cipher, NULL, NULL, NULL);
      /* set the IV length as 128-bits (or 16 bytes) */
      EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_GCM_SET_IVLEN, iv->size(), NULL);
      /* specify key and iv */
      //	cout << "Deckey:\n";
      //	BIO_dump_fp(stdout, (const char *) this->key->getInternalPtr(),
      // this->key->getLength());
      EVP_DecryptInit_ex(this->ctx, NULL, NULL, this->key->getInternalPtr(),
                         iv->getInternalPtr());

      /* set the tag BEFORE any calls to decrypt update
      NOTE: the tag isn't checked until decrypt finalize (i.e., once we've
      obtained all the blocks) */
      EVP_CIPHER_CTX_ctrl(this->ctx, EVP_CTRL_GCM_SET_TAG, tag->size(),
                          tag->getInternalPtr());
      this->init_dec_set = true;
      this->updateDecCount = 0;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::decryptUpdate(OpenABEByteString *ciphertextBlock,
                                                OpenABEByteString *plaintext) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    if (this->init_dec_set) {
      ASSERT_NOTNULL(ciphertextBlock);
      ASSERT(ciphertextBlock->size() > 0, OpenABE_ERROR_INVALID_INPUT);
      /* perform decrypt update */
      int ct_len = ciphertextBlock->size();
      uint8_t *ct_ptr = ciphertextBlock->getInternalPtr();
      int pt_len = 0;

      uint8_t pt[ct_len + 1];
      memset(pt, 0, ct_len + 1);
      /* decrypt and store plaintext in pt buffer */
      EVP_DecryptUpdate(this->ctx, pt, &pt_len, ct_ptr, ct_len);
      ASSERT(pt_len == ct_len, OpenABE_ERROR_BUFFER_TOO_SMALL);
      /* add pt block to the given plaintext buffer */
      plaintext->appendArray(pt, (uint32_t)pt_len);
      this->updateDecCount++;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

OpenABE_ERROR OpenABESymKeyAuthEncStream::decryptFinalize(OpenABEByteString *plaintext) {
  OpenABE_ERROR result = OpenABE_NOERROR;

  try {
    if (this->init_dec_set && this->updateDecCount > 0) {
      /* finalize decryption */
      int pt_len = plaintext->size();
      int retValue =
          EVP_DecryptFinal_ex(this->ctx, plaintext->getInternalPtr(), &pt_len);
      /* clear memory before the check */
      EVP_CIPHER_CTX_free(this->ctx);
      this->ctx = NULL;
      this->updateDecCount = 0;
      // clear some buffers
      this->the_iv.fillBuffer(0, this->the_iv.size());
      this->aad.fillBuffer(0, this->aad.size());
      this->aad_set = false;
      this->init_dec_set = false;

      if (retValue > 0) {
        /* clear memory and return OpenABE_NOERROR */
        throw OpenABE_NOERROR;
      } else {
        /* tag verification failed. therefore, throw a decryption failed error
         */
        throw OpenABE_ERROR_DECRYPTION_FAILED;
      }
    } else {
      throw OpenABE_ERROR_INVALID_INPUT;
    }
  } catch (OpenABE_ERROR &error) {
    result = error;
  }

  return result;
}

}
