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
/// \file   test_ske.cpp
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

#define TEST_MSG_LEN        32
#define TEST_MSGBLOCK_LEN   16

#define TEST_DESCRIPTION(desc) RecordProperty("description", desc)
#define TESTSUITE_DESCRIPTION(desc) ::testing::Test::RecordProperty("description", desc)


TEST(SK, TestStreamAuthEncForSKScheme) {
    TEST_DESCRIPTION("Testing Stream SK scheme enc/dec using randomly generated keys");
    OpenABERNG rng;
    shared_ptr<OpenABESymKey> symkey(new OpenABESymKey);
    OpenABEByteString plaintext, ciphertext, iv, tag;
    OpenABEByteString ptBlock1, ptBlock2, ctBlock1, ctBlock2;

    // generate a random secret key of a certain size
    symkey->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES);

    unique_ptr<OpenABESymKeyAuthEncStream> authEncStream(new OpenABESymKeyAuthEncStream(DEFAULT_AES_SEC_LEVEL, symkey));

    rng.getRandomBytes(&ptBlock1, TEST_MSGBLOCK_LEN);
    rng.getRandomBytes(&ptBlock2, TEST_MSGBLOCK_LEN);

    ASSERT_TRUE(authEncStream->encryptInit(&iv) == OpenABE_NOERROR);
    // set 0s for the AAD
    authEncStream->initAddAuthData(NULL, 0);
    ASSERT_TRUE(authEncStream->setAddAuthData() == OpenABE_NOERROR);

    // perform update 1
    ASSERT_TRUE(authEncStream->encryptUpdate(&ptBlock1, &ciphertext) == OpenABE_NOERROR);

    // perform update 2
    ASSERT_TRUE(authEncStream->encryptUpdate(&ptBlock2, &ciphertext) == OpenABE_NOERROR);
    ASSERT_TRUE(authEncStream->encryptFinalize(&ciphertext, &tag) == OpenABE_NOERROR);

    // split ciphertext into blocks
    ctBlock1 = ciphertext.getSubset(0, ptBlock1.size());
    ctBlock2 = ciphertext.getSubset(ptBlock1.size(), ptBlock2.size());

    // now try to decrypt the ciphertexts
    ASSERT_TRUE(authEncStream->decryptInit(&iv, &tag) == OpenABE_NOERROR);

    // set 0s for the AAD
    authEncStream->initAddAuthData(NULL, 0);
    ASSERT_TRUE(authEncStream->setAddAuthData() == OpenABE_NOERROR);

    // perform decrypt updates in order (note: order of blocks must be managed by the user)
    ASSERT_TRUE(authEncStream->decryptUpdate(&ctBlock1, &plaintext) == OpenABE_NOERROR);
    ASSERT_TRUE(authEncStream->decryptUpdate(&ctBlock2, &plaintext) == OpenABE_NOERROR);
    ASSERT_TRUE(authEncStream->decryptFinalize(&plaintext) == OpenABE_NOERROR);

    ASSERT_TRUE(plaintext == (ptBlock1 + ptBlock2));
    // FAILURE TEST: now try to decrypt the ciphertexts (out of order)
    plaintext.clear();
    ASSERT_TRUE(authEncStream->decryptInit(&iv, &tag) == OpenABE_NOERROR);

    // set 0s for the AAD
    authEncStream->initAddAuthData(NULL, 0);
    ASSERT_TRUE(authEncStream->setAddAuthData() == OpenABE_NOERROR);
    // perform decrypt updates in order (note: order of blocks must be managed by the user)
    ASSERT_TRUE(authEncStream->decryptUpdate(&ctBlock2, &plaintext) == OpenABE_NOERROR);
    ASSERT_TRUE(authEncStream->decryptUpdate(&ctBlock1, &plaintext) == OpenABE_NOERROR);
    ASSERT_FALSE(authEncStream->decryptFinalize(&plaintext) == OpenABE_NOERROR);
}

class KDFNistTestVector : public ::testing::Test {
 protected:
  virtual void SetUp() { }
  string password, salt;
  OpenABEByteString DK, DK0, key, P, S;
  int dkLen, c;
};

TEST_F(KDFNistTestVector, DK1Test) {
    TEST_DESCRIPTION("Testing KDFs are implemented according to RFC 2898: DK1");
    /* PBKDF2 Test Vectors as defined in RFC 6070 */
    /* test 1 */
    uint8_t dk1[] = {0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
                     0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
                     0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
                     0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b}; // (32 octets)
    P     = "password";
    S     = "salt";
    c     = 1;
    dkLen = 32;

    DK.appendArray(dk1, dkLen);
    DK0   = OpenABEPBKDF(P, dkLen, S, c);
    cout << "DK1:     " << DK0.toHex() << endl;
    ASSERT_TRUE(DK == DK0);
}

TEST_F(KDFNistTestVector, DK2Test) {
    TEST_DESCRIPTION("Testing KDFs are implemented according to RFC 2898: DK2");
    /* test 2 */
    uint8_t dk2[] = {0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
                     0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
                     0x2a, 0x30, 0x3f, 0x8e}; // (20 octets)

    DK.clear();
    P     = "password";
    S     = "salt";
    c     = 2;
    dkLen = 20;

    DK.appendArray(dk2, dkLen);
    DK0   = OpenABEPBKDF(P, dkLen, S, c);
    cout << "DK2:     " << DK0.toHex() << endl;
    ASSERT_TRUE(DK == DK0);
}

TEST_F(KDFNistTestVector, DK3Test) {
    TEST_DESCRIPTION("Testing KDFs are implemented according to RFC 2898: DK3");
    /* test 3 is successful but takes a while */
    uint8_t dk3[] = {0xcf, 0x81, 0xc6, 0x6f, 0xe8, 0xcf, 0xc0, 0x4d, 0x1f,
    		         0x31, 0xec, 0xb6, 0x5d, 0xab, 0x40, 0x89, 0xf7, 0xf1,
    		         0x79, 0xe8};
    DK.clear();
    P     = "password";
    S     = "salt";
    c     = 16777216;
    dkLen = 20;

    DK.appendArray(dk3, dkLen);
    DK0   = OpenABEPBKDF(P, dkLen, S, c);
    cout << "DK3:     " << DK0.toHex() << endl;
    ASSERT_TRUE(DK == DK0);
}

TEST_F(KDFNistTestVector, DK4Test) {
    TEST_DESCRIPTION("Testing KDFs are implemented according to RFC 2898: DK4");
    /* test 4 */
    uint8_t dk4[] = {0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f, 0x32,
                     0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf, 0x2b, 0x17,
                     0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18, 0x1c}; // (25 octets)

    DK.clear();
    P     = "passwordPASSWORDpassword"; 		    // (24 octets)
    S     = "saltSALTsaltSALTsaltSALTsaltSALTsalt"; // (36 octets)
    c     = 4096;
    dkLen = 25;

    DK.appendArray(dk4, dkLen);
    DK0   = OpenABEPBKDF(P, dkLen, S, c);
    cout << "DK4:     " << DK0.toHex() << endl;
    ASSERT_TRUE(DK == DK0);
}

TEST_F(KDFNistTestVector, DK5Test) {
    TEST_DESCRIPTION("Testing KDFs are implemented according to RFC 2898: DK5");
    /* test 5 */
    uint8_t dk5[] = {0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89,
                     0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a, 0x86, 0x87}; // (16 octets)
    DK.clear();
    P     = string("pass\0word", 9); // (9 octets)
    S     = string("sa\0lt", 5);    // (5 octets)
    c     = 4096;
    dkLen = 16;

    DK.appendArray(dk5, dkLen);
    DK0   = OpenABEPBKDF(P, dkLen, S, c);
    cout << "DK5:     " << DK0.toHex() << endl;
    ASSERT_TRUE(DK == DK0);
}


TEST(KDF, PasswordHashingSuccess) {
  TEST_DESCRIPTION("Testing that password hashing succeed in general cases");
    string hash1, hash2;
    string password1, password2;

    password1 = "password";
    password2 = "passw0rd";
    generateHash(hash1, password1);
    generateHash(hash2, password2);

    ASSERT_TRUE(checkPassword(hash1, password1));
    ASSERT_FALSE(checkPassword(hash1, password2));
    ASSERT_TRUE(checkPassword(hash2, password2));
    ASSERT_FALSE(checkPassword(hash2, password1));
}

TEST(KDF, CheckPassWithNonHexHashString) {
    TEST_DESCRIPTION("Testing check password with ascii-looking hash string");
    ASSERT_THROW(checkPassword("foosdfasdfasdfasdfasdfasdfasdfadfafoosdfasdfasdfasdfasdfzxyfasdf", "password1"), OpenABE_ERROR);
}

TEST(KDF, CheckPassWithInvalidHexString) {
    TEST_DESCRIPTION("Testing check password with invalid hex string (e.g., 0xff)");
    ASSERT_THROW(checkPassword("123\xff\xff", "password1"), OpenABE_ERROR);
}

TEST(KDF, CheckPassWithEmptyHash) {
    TEST_DESCRIPTION("Testing check password with an empty hash string");
    ASSERT_THROW(checkPassword("", "password1"), OpenABE_ERROR);
}

TEST(KDF, CheckWithEmptyPassword) {
    TEST_DESCRIPTION("Testing check password with an empty password and invalid string");
    string hash;
    generateHash(hash, "password1");
    ASSERT_THROW(checkPassword(hash, ""), OpenABE_ERROR);
}


int main(int argc, char **argv) {
  int rc;

  InitializeOpenABE();

  ::testing::InitGoogleTest(&argc, argv);
  rc = RUN_ALL_TESTS();

  ShutdownOpenABE();

  return rc;
}
