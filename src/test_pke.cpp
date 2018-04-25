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
/// \file   test_pke.cpp
///
/// \brief  Unit testing utility for OpenABE schemes.
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <gtest/gtest.h>

#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

#define TEST_MSG_LEN                32
#define DEFAULT_PARAMETER_STRING    "NIST_P256"
#define TEST_DESCRIPTION(desc) RecordProperty("description", desc)
#define TESTSUITE_DESCRIPTION(desc) ::testing::Test::RecordProperty("description", desc)


TEST(PK_ODPH, TestCCASecurityForScheme) {
    TEST_DESCRIPTION("Testing CCA-secure PK OPDH context with randomly generated messages");
  OpenABEByteString bytes, ctBlob, hdr1, hdr2;
  string plaintext1, plaintext2;
  OpenABECiphertext ciphertext, ciphertext2;
  OpenABERNG rng;
  rng.getRandomBytes(&bytes, TEST_MSG_LEN);
  plaintext1 = bytes.toString();
  // create new KEM context for PKE ECC MQV scheme
  unique_ptr<OpenABEContextSchemePKE> schemeContext = OpenABE_createContextPKESchemeCCA(OpenABE_SCHEME_PK_OPDH);
  ASSERT_TRUE(schemeContext != nullptr);

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(schemeContext->generateParams(DEFAULT_PARAMETER_STRING) == OpenABE_NOERROR);

  // Compute party A's static public and private key
  ASSERT_TRUE(schemeContext->keygen("ID_A", "public_A", "private_A") == OpenABE_NOERROR);

  // Compute party B's static public and private key
  ASSERT_TRUE(schemeContext->keygen("ID_B", "public_B", "private_B") == OpenABE_NOERROR);

  // Test load / delete (perhaps, we should provide convenience functions for this)
  OpenABEByteString publicKeyA, publicKeyA_bad, privateKeyB;

  schemeContext->exportKey("public_A", publicKeyA);
  schemeContext->exportKey("private_B", privateKeyB);

  publicKeyA_bad = publicKeyA;
  // swap two positions in header
  publicKeyA_bad[5] = publicKeyA_bad[6]; // tweak header a little bit
  publicKeyA_bad[6] = publicKeyA[5];

  // delete them
  ASSERT_TRUE(schemeContext->deleteKey("public_A") == OpenABE_NOERROR);
  ASSERT_TRUE(schemeContext->deleteKey("private_B") == OpenABE_NOERROR);

  // attempt to load a key that was just deleted
  ASSERT_FALSE(schemeContext->loadPublicKey("public_A", publicKeyA_bad) == OpenABE_NOERROR);

  // attempt to load a key that was just deleted
  ASSERT_TRUE(schemeContext->loadPublicKey("public_A", publicKeyA) == OpenABE_NOERROR);

  // attempt to load a key that was just deleted
  ASSERT_TRUE(schemeContext->loadPrivateKey("private_B", privateKeyB) == OpenABE_NOERROR);

  ASSERT_TRUE(schemeContext->encrypt(NULL, "public_B", "public_A", plaintext1, &ciphertext) == OpenABE_NOERROR);

  ciphertext.exportToBytes(ctBlob);
  ciphertext2.loadFromBytes(ctBlob);
  ASSERT_TRUE(ciphertext == ciphertext2);
  // verify header is thesame
  ciphertext.getHeader(hdr1);
  ciphertext2.getHeader(hdr2);
  ASSERT_TRUE(hdr1 == hdr2);

  ASSERT_TRUE(schemeContext->decrypt("public_A", "private_B", plaintext2, &ciphertext2) == OpenABE_NOERROR);

  ASSERT_TRUE(plaintext1.compare(plaintext2) == 0);
}


int main(int argc, char **argv) {
  int rc;

  InitializeOpenABE();

  ::testing::InitGoogleTest(&argc, argv);
  rc = RUN_ALL_TESTS();

  ShutdownOpenABE();

  return rc;
}
