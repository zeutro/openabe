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
/// \file   zpkey.cpp
///
/// \brief  Implementation for storing OpenABE keys for PKSIG schemes.
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEPKey class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEPKey class.
 *
 */
OpenABEPKey::OpenABEPKey(bool isPrivate) : OpenABEKey() {
  this->pkey = NULL;
  this->isPrivate = isPrivate;
}

/*!
 * Constructor for the OpenABEPKey class.
 *
 */
OpenABEPKey::OpenABEPKey(const EC_KEY *ec_key, bool isPrivate, EC_GROUP *group)
    : OpenABEKey() {
  EC_KEY *new_eckey = NULL;
  EC_GROUP *new_group = NULL;
  this->pkey = EVP_PKEY_new();
  this->isPrivate = isPrivate;
  string error_msg = "";
  // check whether private or public key
  if (this->isPrivate) {
    // set as the EC_KEY (private key) of the pkey
    // no need to copy since it'll be owned by the pkey
    EVP_PKEY_assign_EC_KEY(this->pkey, ec_key);
  } else {
    ASSERT_NOTNULL(group);
    // create a new EC_GROUP from the group of eckey, this
    // will also copy over the ASN1 flag
    new_group = EC_GROUP_dup(group);
    if (!new_group) {
      goto error;
    }

    new_eckey = EC_KEY_new();
    if (!new_eckey) {
      goto error;
    }

    if (EC_KEY_set_group(new_eckey, new_group) == 0) {
      goto error;
    }

    // makes a copy of the public key
    if (!EC_KEY_set_public_key(new_eckey, EC_KEY_get0_public_key(ec_key))) {
      error_msg = "EC_KEY_set_public_key failed";
      goto error;
    }

    // set the EC_KEY field of the EVP_PKEY
    EVP_PKEY_assign_EC_KEY(this->pkey, new_eckey);
    if (new_group != NULL) {
      EC_GROUP_free(new_group);
    }
  }
  return;
error:
  if (new_eckey != NULL) {
    EC_KEY_free(new_eckey);
  }

  if (new_group != NULL) {
    EC_GROUP_free(new_group);
  }

  if (error_msg != "") {
    OpenABE_LOG(error_msg);
  }

  throw OpenABE_ERROR_ELEMENT_NOT_INITIALIZED;
}

/*!
 * Destructor for the OpenABEPKey class.
 *
 */
OpenABEPKey::~OpenABEPKey() {
  if (this->pkey != NULL) {
    EVP_PKEY_free(this->pkey);
  }
}


OpenABE_ERROR
OpenABEPKey::exportKeyToBytes(OpenABEByteString &output) {
  OpenABE_ERROR result = OpenABE_ERROR_INVALID_INPUT;
  BIO *pkey_out = nullptr;
  string pkey_text, s;
  stringstream ss;

  ASSERT_NOTNULL(this->pkey);

  pkey_out = BIO_new(BIO_s_mem());
  if (!pkey_out) {
    goto out;
  }

  if (this->isPrivate) {
    // write private key
    if (!PEM_write_bio_PKCS8PrivateKey(pkey_out, this->pkey, NULL, NULL, 0,
                                       NULL, NULL)) {
      goto out;
    }
  } else {
    // write public key
    if (!PEM_write_bio_PUBKEY(pkey_out, this->pkey)) {
      goto out;
    }
  }

  // Unfortunately Thrift requires a signature key to be in OpenSSL
  // format, so we keep that format exactly.  If you look in the
  // history for this file, you will find some metadata we kept with
  // keys that we could reinstate by patching Thrift.
  if (!bioToString(s, pkey_out)) {
    goto out;
  }
  output = s;
  result = OpenABE_NOERROR;

out:
  if (pkey_out) {
    BIO_free(pkey_out);
  }

  return result;
}

OpenABE_ERROR
OpenABEPKey::loadKeyFromBytes(OpenABEByteString &input) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  BIO *bio = NULL;

  // cout << "Serialized Key:\n" << input.toString() << endl;

  bio = BIO_new_mem_buf((void *)input.getInternalPtr(), input.size());
  if (!bio) {
    result = OpenABE_ERROR_INVALID_INPUT;
    goto out;
  }

  if (this->pkey != NULL) {
    EVP_PKEY_free(this->pkey);
    this->pkey = NULL;
  }

  if (this->isPrivate) {
    this->pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  } else {
    this->pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  }
  ASSERT_NOTNULL(this->pkey);

  if (!this->pkey) {
    result = OpenABE_ERROR_DESERIALIZATION_FAILED;
    goto out;
  }

out:
  if (bio) {
    BIO_free(bio);
  }

  return result;
}

bool OpenABEPKey::bioToString(string &s, BIO *bio) {
  bool result = false;
  char buf[512];
  int rc;

  s.clear();
  while ((rc = BIO_read(bio, buf, sizeof(buf))) > 0) {
    char *end = buf;
    end += rc;
    s.append(buf, end);
  }

  if (BIO_eof(bio)) {
    result = true;
  }
  return result;
}

}
