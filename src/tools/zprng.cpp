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
/// \file   zprng.cpp
///
/// \brief  Implementation for OpenABE RNG/PRNG
///
/// \author Matthew Green and J. Ayo Akinyele
///

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <openabe/openabe.h>
#include <openssl/evp.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEPRNG class
 ********************************************************************************/
namespace oabe {

OpenABERNG::OpenABERNG(): ZObject() {
}

OpenABERNG::~OpenABERNG() {
}

/********************************************************************************
 * Implementation of the OpenABEPRNG class
 ********************************************************************************/

static void AesEvpBlockEncrypt(const EVP_CIPHER *cipher, const uint8_t* key,
                        const uint8_t* pl_ptr, uint8_t *ct_ptr, size_t pl_len) {
    ASSERT_NOTNULL(cipher);
    EVP_CIPHER_CTX *ctx = nullptr;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, false);
    // note that cipher AND key must be in sync (key len should be appropriate input size of
    // cipher (e.g., 128-bits by default)
    EVP_EncryptInit_ex (ctx, cipher, NULL, (uint8_t*)key, NULL);
    
    int olen = 512, tmp_len, out_len;
    uint8_t out[olen];
    memset(out, 0, olen);
    EVP_EncryptUpdate(ctx, out, &tmp_len, (uint8_t*) pl_ptr, (int)pl_len);

    EVP_EncryptFinal_ex(ctx, out + tmp_len, &out_len);
    // check that tmp_len == out_len
    // copy back the output ciphertext
    memcpy(ct_ptr, out, out_len);
    // cleanup memory
    EVP_CIPHER_CTX_free(ctx);
}

static void AES_ECB(const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext, size_t len) {
    // make sure key and plaintext are of sufficient length
    const EVP_CIPHER *cipher = EVP_aes_256_ecb();
    AesEvpBlockEncrypt(cipher, key, plaintext, ciphertext, len);
}

//static void AES_CTR(const uint8_t *key, const uint8_t *plaintext, size_t len) {
//    // 1. need an IV too here
//    // 2. make sure key and plaintext are of sufficient length
//    AesEvpBlockEncrypt(EVP_aes_256_ctr(), key, plaintext, len);
//}

static void initCtrDrbgContext(OpenABECtrDrbg& ctx, uint8_t *key, size_t key_len) {
    memcpy(ctx->key, key, key_len);
    OpenABEZeroize(ctx->counter, AES_BLOCK_SIZE);
    ctx->reseed_counter = 0;
    ctx->reseed_interval = OpenABE_CTR_DRBG_RESEED_INTERVAL;
}

static void clearCtrDrbgContext(OpenABECtrDrbg& ctx) {
    OpenABEZeroize(ctx->key, OpenABE_CTR_DRBG_KEYSIZE_BYTES);
    OpenABEZeroize(ctx->counter, AES_BLOCK_SIZE);
    ctx->reseed_counter = 0;
    ctx->reseed_interval = 0;
    ctx->entropy_src = NULL;
    ctx->entropy_callback = NULL;
}

int ctr_drbg_seed_entropy_len(OpenABECtrDrbg& ctx,
                   int (*entropy_callback)(void *, unsigned char *, size_t),
                   void *entropy_src,
                   const uint8_t *person_string,
                   size_t person_string_len,
                   size_t entropy_len) {
    int result;

    uint8_t key[OpenABE_CTR_DRBG_KEYSIZE_BYTES];
    memset(key, 0, OpenABE_CTR_DRBG_KEYSIZE_BYTES);
    // Initialize with an empty key
    initCtrDrbgContext(ctx, key, OpenABE_CTR_DRBG_KEYSIZE_BYTES);
    // Set the entropy callback function
    ctx->entropy_callback = entropy_callback;
    // Set the entropy source buffer
    ctx->entropy_src = entropy_src;
    // Set the entropy length
    ctx->entropy_len = entropy_len;
    // Do an initial reseed
    if ((result = ctr_drbg_reseed(ctx, person_string, person_string_len)) != 0)
        return result;
    return 0;
}

//static void debug(const string msg, uint8_t *buf, size_t len) {
//    OpenABEByteString tmp_buf;
//    tmp_buf.appendArray(buf, len);
//    cout << msg << tmp_buf.toLowerHex() << endl;
//}

static int block_cipher_df(uint8_t *output, const uint8_t *data, size_t data_len) {
    int max_buf_len = OpenABE_CTR_DRBG_MAX_SEED_INPUT + OpenABE_CTR_DRBG_BLOCKSIZE + 16;
    uint8_t buf[max_buf_len];
    uint8_t tmp[OpenABE_CTR_DRBG_SEEDLEN];
    uint8_t key[OpenABE_CTR_DRBG_KEYSIZE_BYTES];
    uint8_t chain[OpenABE_CTR_DRBG_BLOCKSIZE];
    uint8_t *p, *iv;
    size_t i, j;
    size_t buf_len, use_len;

    if (data_len > OpenABE_CTR_DRBG_MAX_SEED_INPUT)
        return OpenABE_ERR_CTR_DRBG_INPUT_TOO_BIG;

    memset(buf, 0, max_buf_len);
    /*
     * Construct IV (16 bytes) and S in buffer
     * IV = Counter (in 32-bits) padded to 16 with zeroes
     * S = Length input string (in 32-bits) || Length of output (in 32-bits) ||
     *     data || 0x80
     *     (Total is padded to a multiple of 16-bytes with zeroes)
     */
    p = buf + OpenABE_CTR_DRBG_BLOCKSIZE;
    *p++ = ( data_len >> 24 ) & 0xFF;
    *p++ = ( data_len >> 16 ) & 0xFF;
    *p++ = ( data_len >> 8  ) & 0xFF;
    *p++ = ( data_len       ) & 0xFF;
    p += 3;
    *p++ = OpenABE_CTR_DRBG_SEEDLEN;
    memcpy(p, data, data_len);
    p[data_len] = 0x80;

    buf_len = OpenABE_CTR_DRBG_BLOCKSIZE + 8 + data_len + 1;

    for (i = 0; i < OpenABE_CTR_DRBG_KEYSIZE_BYTES; i++) {
        key[i] = i;
    }

    // Reduce data to OpenABE_CTR_DRBG_SEEDLEN bytes of data
    for (j = 0; j < OpenABE_CTR_DRBG_SEEDLEN; j += OpenABE_CTR_DRBG_BLOCKSIZE) {
        p = buf;
        memset(chain, 0, OpenABE_CTR_DRBG_BLOCKSIZE);
        use_len = buf_len;

        while (use_len > 0) {
            for (i = 0; i < OpenABE_CTR_DRBG_BLOCKSIZE; i++)
                chain[i] ^= p[i];
            p += OpenABE_CTR_DRBG_BLOCKSIZE;
            use_len -= (use_len >= OpenABE_CTR_DRBG_BLOCKSIZE) ?
                       OpenABE_CTR_DRBG_BLOCKSIZE : use_len;
            // Block encrypt
            AES_ECB(key, chain, chain, OpenABE_CTR_DRBG_BLOCKSIZE);
        }

        memcpy(tmp + j, chain, OpenABE_CTR_DRBG_BLOCKSIZE);
        // Update IV
        buf[3]++;
    }

    // Final encryption with reduced data
    memcpy(key, tmp, OpenABE_CTR_DRBG_KEYSIZE_BYTES);
    iv = tmp + OpenABE_CTR_DRBG_KEYSIZE_BYTES;
    p = output;

    for (j = 0; j < OpenABE_CTR_DRBG_SEEDLEN; j += OpenABE_CTR_DRBG_BLOCKSIZE) {
        // Block encrypt
        AES_ECB(key, iv, iv, OpenABE_CTR_DRBG_BLOCKSIZE);
        memcpy(p, iv, OpenABE_CTR_DRBG_BLOCKSIZE);
        p += OpenABE_CTR_DRBG_BLOCKSIZE;
    }

    return 0;
}

static int update_internal(OpenABECtrDrbg& ctx, const uint8_t data[OpenABE_CTR_DRBG_SEEDLEN]) {
    unsigned char tmp[OpenABE_CTR_DRBG_SEEDLEN];
    unsigned char *p = tmp;
    size_t i, j;

    memset( tmp, 0, OpenABE_CTR_DRBG_SEEDLEN );

    for (j = 0; j < OpenABE_CTR_DRBG_SEEDLEN; j += OpenABE_CTR_DRBG_BLOCKSIZE) {
        // Increase counter
        for (i = OpenABE_CTR_DRBG_BLOCKSIZE; i > 0; i--)
            if (++ctx->counter[i - 1] != 0)
                break;

        // Encrypt counter block
        AES_ECB(ctx->key, ctx->counter, p, OpenABE_CTR_DRBG_BLOCKSIZE);
        p += OpenABE_CTR_DRBG_BLOCKSIZE;
    }

    for (i = 0; i < OpenABE_CTR_DRBG_SEEDLEN; i++) {
        tmp[i] ^= data[i];
    }

     // Update key and counter
    memcpy(ctx->key, tmp, OpenABE_CTR_DRBG_KEYSIZE_BYTES);
    memcpy(ctx->counter, tmp + OpenABE_CTR_DRBG_KEYSIZE_BYTES, OpenABE_CTR_DRBG_BLOCKSIZE );

    return 0;
}

void ctr_drbg_update(OpenABECtrDrbg& ctx, const uint8_t *additional, size_t add_len) {
    uint8_t add_input[OpenABE_CTR_DRBG_SEEDLEN];

    if (add_len > 0) {
        if (add_len > OpenABE_CTR_DRBG_MAX_SEED_INPUT) {
            add_len = OpenABE_CTR_DRBG_MAX_SEED_INPUT;
        }
        block_cipher_df(add_input, additional, add_len);
        // Update internal state of K and V
        update_internal(ctx, add_input);
    }
}

int ctr_drbg_reseed(OpenABECtrDrbg& ctx, const uint8_t *additional, size_t len) {
    uint8_t seed[OpenABE_CTR_DRBG_MAX_SEED_INPUT];
    size_t seedlen = 0;
    // make sure entropy len is less than max input
    if (ctx->entropy_len + len > OpenABE_CTR_DRBG_MAX_SEED_INPUT) {
        return OpenABE_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }
    memset(seed, 0, OpenABE_CTR_DRBG_MAX_SEED_INPUT);
    // Copy entropy_len bytes of entropy to seed
    if (ctx->entropy_callback(ctx->entropy_src, seed, ctx->entropy_len) != 0) {
        return OpenABE_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    seedlen += ctx->entropy_len;
    // Add additional data (only if additional is not null)
    if (additional && len) {
        memcpy(seed + seedlen, additional, len);
        seedlen += len;
    }

    // Reduce or stretch to 384 bits
    block_cipher_df(seed, seed, seedlen);
    // Update internal state of K and V
    update_internal(ctx, seed);
    // Reset the reseed counter
    ctx->reseed_counter = 1;
    return 0;
}

int ctr_drbg_init_seed(OpenABECtrDrbg& ctx,
                  int (*entropy_callback)(void *, uint8_t *, size_t),
                  OpenABEByteString& entropy_source_buf,
                  const uint8_t *nonce,
                  size_t nonce_len) {
    // make sure entropy_source_buf is right length
    if (entropy_source_buf.size() < OpenABE_CTR_DRBG_ENTROPYLEN) {
        throw OpenABE_ERROR_INVALID_LENGTH;
    }
    return ctr_drbg_seed_entropy_len(ctx, entropy_callback, (uint8_t *)entropy_source_buf.getInternalPtr(),
                                     nonce, nonce_len,
                                     OpenABE_CTR_DRBG_ENTROPYLEN);
}

int ctr_drbg_generate_random_with_add(OpenABECtrDrbg& ctx, uint8_t *output, size_t output_len,
                     const uint8_t *additional, size_t add_len) {
    int ret = 0;
    uint8_t add_input[OpenABE_CTR_DRBG_SEEDLEN];
    uint8_t *p = output;
    uint8_t tmp[OpenABE_CTR_DRBG_BLOCKSIZE];
    int i;
    size_t use_len;

    if (output_len > OpenABE_CTR_DRBG_MAX_REQUEST) {
        return OpenABE_ERR_CTR_DRBG_REQUEST_TOO_BIG;
    }
    if (add_len > OpenABE_CTR_DRBG_MAX_INPUT_LENGTH) {
        return OpenABE_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }
    memset(add_input, 0, OpenABE_CTR_DRBG_SEEDLEN);

    // Reseed if counter is greater than reseed interval
    if (ctx->reseed_counter > ctx->reseed_interval) {
        if ((ret = ctr_drbg_reseed(ctx, additional, add_len)) != 0)
            return ret;
        add_len = 0;
    }

    if (add_len > 0) {
        // Reduce additional input to 384-bits (default)
        block_cipher_df(add_input, additional, add_len);
        // Update internal state of K and V
        update_internal(ctx, add_input);
    }

    while (output_len > 0) {
        // Increase counter
        for (i = OpenABE_CTR_DRBG_BLOCKSIZE; i > 0; i--) {
            if(++ctx->counter[i - 1] != 0)
                break;
        }
        // Block_encrypt
        AES_ECB(ctx->key, ctx->counter, tmp, OpenABE_CTR_DRBG_BLOCKSIZE);
        use_len = (output_len > OpenABE_CTR_DRBG_BLOCKSIZE) ? OpenABE_CTR_DRBG_BLOCKSIZE :
                                                       output_len;
        // Copy random block to destination
        memcpy(p, tmp, use_len);
        p += use_len;
        output_len -= use_len;
    }
    // Update internal K and V
    update_internal(ctx, add_input);
    ctx->reseed_counter++;

    return 0;
}

OpenABECtrDrbgContext::OpenABECtrDrbgContext(OpenABEByteString &entropy) {
    ctx_.reset(new OpenABECtrDrbg_);
    ASSERT(entropy.size() >= OpenABE_CTR_DRBG_ENTROPYLEN, OpenABE_ERROR_INVALID_LENGTH);
    short_entropy_ = entropy;
}

OpenABECtrDrbgContext::OpenABECtrDrbgContext(const uint8_t *entropy, uint32_t entropy_len) {
    ctx_.reset(new OpenABECtrDrbg_);
    ASSERT(entropy_len >= OpenABE_CTR_DRBG_ENTROPYLEN, OpenABE_ERROR_INVALID_LENGTH);
    short_entropy_.appendArray((uint8_t *)entropy, entropy_len);
}

OpenABECtrDrbgContext::~OpenABECtrDrbgContext() {
    short_entropy_.zeroize();
    clearCtrDrbgContext(ctx_);
}

void
OpenABECtrDrbgContext::initSeed(int (*entropy_func)(void *, uint8_t *, size_t),
                     const uint8_t *nonce, size_t nonce_len) {
    ctr_drbg_init_seed(ctx_, entropy_func, short_entropy_, nonce, nonce_len);
}

static int entropy_callback(void *data, uint8_t *target_buf, size_t target_len) {
    const uint8_t *src = (uint8_t *)data;
    memcpy(target_buf, src, target_len);
    return 0;
}

void
OpenABECtrDrbgContext::initSeed(const uint8_t *nonce, size_t nonce_len) {
    ctr_drbg_init_seed(ctx_, entropy_callback, short_entropy_, nonce, nonce_len);
}


int OpenABECtrDrbgContext::getRandomBytes(uint8_t *output, size_t output_len) {
    // make sure we've called init on ctx. otherwise, throw an error
    std::lock_guard<std::mutex> write_lock(lock_);
    return ctr_drbg_generate_random_with_add(ctx_, output, output_len, NULL, 0);
}

int OpenABECtrDrbgContext::getRandomBytes(OpenABEByteString *output, size_t output_len) {
    output->clear();
    std::lock_guard<std::mutex> write_lock(lock_);
    return ctr_drbg_generate_random_with_add(ctx_, (uint8_t*)output->getInternalPtr(), output_len, NULL, 0);
}

int OpenABECtrDrbgContext::reSeed(const uint8_t *buf_ptr, size_t buf_len) {
    return ctr_drbg_reseed(ctx_, buf_ptr, buf_len);
}

int OpenABECtrDrbgContext::reSeed(OpenABEByteString *buf) {
    uint8_t *buf_ptr = NULL;
    size_t buf_len = 0;

    if (buf != nullptr) {
        buf_ptr = buf->getInternalPtr();
        buf_len = buf->size();
    }
    return this->reSeed(buf_ptr, buf_len);
}

OpenABECTR_DRBG::OpenABECTR_DRBG(OpenABEByteString& entropy): isInit_(false) {
    ctrDrbgContext_.reset(new OpenABECtrDrbgContext(entropy));
}

OpenABECTR_DRBG::OpenABECTR_DRBG(uint8_t *entropy_buf, uint32_t entropy_len): isInit_(false) {
    ctrDrbgContext_.reset(new OpenABECtrDrbgContext(entropy_buf, entropy_len));
}

void
OpenABECTR_DRBG::setSeed(OpenABEByteString& nonce) {
    ctrDrbgContext_->initSeed(nonce.getInternalPtr(), nonce.size());
    isInit_ = true;
}

int OpenABECTR_DRBG::getRandomBytes(uint8_t *buf, size_t buf_len) {
    ASSERT(isInit_, OpenABE_ERROR_CTR_DRB_NOT_INITIALIZED);
    int ret = ctrDrbgContext_->getRandomBytes(buf, buf_len);
    if (ret < 0) {
        return 0;
    }
    // means we're good
    return 1;
}

int OpenABECTR_DRBG::getRandomBytes(OpenABEByteString *buf, size_t buf_len) {
    ASSERT(isInit_, OpenABE_ERROR_CTR_DRB_NOT_INITIALIZED);
    uint8_t out[buf_len];
    buf->clear();
    int ret = ctrDrbgContext_->getRandomBytes(out, buf_len);
    if (ret < 0) {
        // an error occurred
        return 0;
    }
    buf->appendArray(out, buf_len);
    memset(out, 0, buf_len);
    return 1; // means we're good
}



}
