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
/// \file   zprng.h
///
/// \brief  Class definition for a pseudorandom generator.
///
/// \author J. Ayo Akinyele
///

#ifndef __ZPRNG_H__
#define __ZPRNG_H__

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <mutex>

#define OpenABE_CTR_DRBG_BLOCKSIZE         16      /* Cipher Block size */
#define OpenABE_CTR_DRBG_KEYSIZE_BYTES     32      /* Cipher Key size in bytes */
#define OpenABE_CTR_DRBG_KEYSIZE_BITS      ( OpenABE_CTR_DRBG_KEYSIZE_BYTES * 8 )
#define OpenABE_CTR_DRBG_SEEDLEN           ( OpenABE_CTR_DRBG_KEYSIZE_BYTES + OpenABE_CTR_DRBG_BLOCKSIZE )
#define OpenABE_CTR_DRBG_NONCELEN          16      /* Default nonce length */
#define OpenABE_CTR_DRBG_ENTROPYLEN        32      /* Amount of entropy used per seed by default
                                                  (32 with SHA-256, 48 with SHA-512, etc) */

#define OpenABE_CTR_DRBG_RESEED_INTERVAL    10000   /* Interval before re-seed is performed by default */
#define OpenABE_CTR_DRBG_MAX_INPUT_LENGTH   256     /* Maximum number of additional input bytes */
#define OpenABE_CTR_DRBG_MAX_REQUEST        1024    /* Maximum number of requested bytes per call */
#define OpenABE_CTR_DRBG_MAX_SEED_INPUT     384     /* Maximum size of (re)seed buffer */

#define OpenABE_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED  -0x0034  /* The entropy source failed. */
#define OpenABE_ERR_CTR_DRBG_REQUEST_TOO_BIG        -0x0036  /* Too many random requested in single call. */
#define OpenABE_ERR_CTR_DRBG_INPUT_TOO_BIG          -0x0038  /* Input too large (Entropy + additional). */


/// \class	OpenABERNG
/// \brief	Abstract base class class for generating randomness
namespace oabe {

class OpenABERNG : public ZObject {
public:
	OpenABERNG();
	~OpenABERNG();

	virtual void setSeed(OpenABEByteString& nonce) { return; }
	virtual int getRandomBytes(uint8_t *buf, size_t buf_len) {
	    ASSERT_RNG(RAND_bytes(buf, buf_len)); return 1;
	}
	virtual int getRandomBytes(OpenABEByteString *buf, size_t buf_len) {
		buf->clear();
		buf->fillBuffer(0, buf_len);
		ASSERT_RNG(RAND_bytes(buf->getInternalPtr(), buf_len));
		return 1;
	}
};

struct OpenABECtrDrbg_ {
  uint8_t key[OpenABE_CTR_DRBG_KEYSIZE_BYTES];
  uint8_t counter[AES_BLOCK_SIZE]; /* counter (V) - default: 256-bit counter */
  int reseed_counter, reseed_interval;
  size_t entropy_len;

  // Callbacks (Entropy)
  int (*entropy_callback)(void *, uint8_t *, size_t);
  //  context for the entropy function
  void *entropy_src;
};
typedef std::shared_ptr<OpenABECtrDrbg_> OpenABECtrDrbg;

/*!
 * \brief               CTR_DRBG update state
 *
 * \param ctx           CTR_DRBG object reference
 * \param additional    additional data to update state
 * \param add_len       length of additional data
 *
 * \note                If add_len is greater than OpenABE_CTR_DRBG_MAX_SEED_INPUT,
 *                      only the first OpenABE_CTR_DRBG_MAX_SEED_INPUT bytes are used,
 *                      the remaining bytes are discarded.
 */
void ctr_drbg_update(OpenABECtrDrbg& ctx, const uint8_t *additional, size_t add_len);

/*!
 * \brief               CTR_DRBG re-seeding (extracts data from entropy source)
 *
 * \param ctx           CTR_DRBG object reference
 * \param additional    additional data to add to state (Can be NULL)
 * \param len           length of additional data
 *
 * \return              0 if successful, or
 *                      OpenABE_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
 */
int ctr_drbg_reseed(OpenABECtrDrbg& ctx, const uint8_t *additional, size_t len);

/*!
 * \brief               CTR_DRBG generate random with additional update input
 *
 * \param ctx           CTR_DRBG object reference
 * \param output        Buffer to fill
 * \param output_len    Length of the buffer
 * \param additional    Additional data to update with (Can be NULL)
 * \param add_len       Length of additional data
 *
 * Note: Automatically reseeds if reseed_counter is reached.
 *
 * \return              0 if successful, or
 *                      OpenABE_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED, or
 *                      OpenABE_ERR_CTR_DRBG_REQUEST_TOO_BIG
 */
int ctr_drbg_generate_random_with_add(OpenABECtrDrbg& ctx, uint8_t *output, size_t output_len,
                                      const uint8_t *additional, size_t add_len);
/*!
 * \brief               CTR_DRBG initial seeding
 *                      Seed and setup entropy source for future reseeds.
 *
 * Note: Personalization data can be provided in addition to the more generic
 *       entropy source to try to make each instantiation unique.
 *
 * \param ctx               CTR_DRBG object to be seeded
 * \param entropy_callback  Entropy callback (entropy_buf, buffer to fill, buffer
 *                          length)
 * \param entropy_buf       Entropy context
 * \param person_str        Personalization string (Device specific identifiers)
 *                          (Can be NULL)
 * \param len               Length of personalization data
 *
 * \return 0 if successful, or OpenABE_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED
 */
int ctr_drbg_init_seed(OpenABECtrDrbg& ctx,
                  int (*entropy_callback)(void *, uint8_t *, size_t),
                  void *entropy_buf,
                  const uint8_t *person_str,
                  size_t len);

/// \class  OpenABECtrDrbgContext
/// \brief  Class/Context implementation for CTR_DRBG NIST Standard
///         Reference: NIST SP 800-90A, Rev 1.
//          Section 10.2 titled "DRBG mechanisms based on Block Ciphers"
class OpenABECtrDrbgContext {
private:
  OpenABECtrDrbg ctx_;
  OpenABEByteString short_entropy_;
  std::mutex lock_;

public:
  OpenABECtrDrbgContext(OpenABEByteString &entropy);
  OpenABECtrDrbgContext(const uint8_t *entropy, uint32_t entropy_len);
  ~OpenABECtrDrbgContext();

  // for nist self test
  void initSeed(int (*entropy_callback)(void *, uint8_t *, size_t),
                const uint8_t *nonce, size_t nonce_len);
  // uses short_entropy
  void initSeed(const uint8_t *nonce, size_t nonce_len);

  int reSeed(const uint8_t *buf_ptr, size_t buf_len);
  int reSeed(OpenABEByteString *buf);

  int getRandomBytes(uint8_t *buf, size_t buf_len);
  int getRandomBytes(OpenABEByteString *buf, size_t buf_len);
};

/// \class  OpenABECTR_DRBG
/// \brief  Thin wrapper around the OpenABECtrDrbgContext
class OpenABECTR_DRBG : public OpenABERNG {
private:
  bool isInit_;
  std::unique_ptr<OpenABECtrDrbgContext> ctrDrbgContext_;

public:
  OpenABECTR_DRBG(OpenABEByteString &entropy);
  OpenABECTR_DRBG(uint8_t *key, uint32_t key_len);
  ~OpenABECTR_DRBG() { };

  void setSeed(OpenABEByteString& nonce);
  int getRandomBytes(uint8_t *buf, size_t buf_len);
  int getRandomBytes(OpenABEByteString *buf, size_t buf_len);
};


}

#endif /* ifdef __ZPRNG_H__ */
