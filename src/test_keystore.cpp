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
/// \file   src/utils/test_keystore.cpp
///
/// \brief  Testing Keystore manager functionality
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <math.h>
#include <gtest/gtest.h>

#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

#define TEST_MSG_LEN    32
#define TEST_DESCRIPTION(desc) RecordProperty("description", desc)

namespace {

class Config {
public:
    Config(OpenABE_SCHEME scheme, const string keyList, const string theFuncInput) {
        scheme_type = scheme;
        // format: 'Alice,Bob:Charlie,David:Eve,Frank' etc
        keyInputs   = oabe::split(keyList, ':');
        funcInput   = theFuncInput;
    }
    ~Config() {};

    OpenABE_SCHEME scheme_type;
    vector<string> keyInputs;
    string funcInput;
};

class KeystoreManagerTest : public ::testing::TestWithParam<Config> {
protected:
    virtual void SetUp() {
        rng_.reset(new OpenABERNG);
        rng_->getRandomBytes(&plaintext, TEST_MSG_LEN);
        MPK = "testMPK";
        MSK = "testMSK";
    }

    unique_ptr<OpenABEFunctionInput> getEncInput(OpenABE_SCHEME type, const string func_input) {
        if(type == OpenABE_SCHEME_CP_WATERS)
            return createPolicyTree(func_input);
        else if(type == OpenABE_SCHEME_KP_GPSW)
            return createAttributeList(func_input);
        return nullptr;
    }

    unique_ptr<OpenABEFunctionInput> getKeyInput(OpenABE_SCHEME type, string key_input) {
        if(type == OpenABE_SCHEME_CP_WATERS)
            return createAttributeList(key_input);
        else if(type == OpenABE_SCHEME_KP_GPSW)
            return createPolicyTree(key_input);
        return nullptr;
    }

    const string printScheme(OpenABE_SCHEME type) {
        switch(type) {
            case OpenABE_SCHEME_CP_WATERS:
                return "CP-ABE"; break;
            case OpenABE_SCHEME_KP_GPSW:
                return "KP-ABE"; break;
            default:
                break;
        }
        return "None";
    }

    OpenABEByteString mpkBlob, mskBlob, skBlob, ctBlob;
    OpenABEByteString plaintext, plaintext1, plaintext2, plaintext3;
    unique_ptr<OpenABERNG> rng_;
    string MPK, MSK, AUTH1MPK, AUTH1MSK, AUTH2MPK, AUTH2MSK;
};


TEST_P(KeystoreManagerTest, testBaseCases) {
    Config input = GetParam();
	TEST_DESCRIPTION("Testing keystore manager works with basic test cases for " + printScheme(input.scheme_type));
    OpenABECiphertext ciphertext;
    OpenABE_SCHEME scheme_type = input.scheme_type;
    const string userId = "user";

    cout << "* Testing keystore management for " << printScheme(scheme_type) << " schemes..." << endl;
    unique_ptr<OpenABEContextSchemeCPA> schemeContext = OpenABE_createContextABESchemeCPA(scheme_type);
    // where each string represents a list of attributes or a policy string
    vector<string> keyInput = input.keyInputs;

    map<string,OpenABEByteString> keyBlobs;
    OpenABEByteString tmp;
    unique_ptr<OpenABEFunctionInput> keyInput1 = nullptr;

    // generate scheme parameters and keys
    schemeContext->generateParams(DEFAULT_BP_PARAM, MPK, MSK);
    for(size_t i = 0; i < keyInput.size(); i++) {
        const string keyID = "key"+to_string(i+1);
        keyInput1 = getKeyInput(scheme_type, keyInput[i]);
        cout << "Generate " << keyID << ": " << keyInput1->toString() << endl;
        schemeContext->keygen((OpenABEFunctionInput *)keyInput1.get(), keyID, MPK, MSK);
        schemeContext->exportKey(keyID, tmp);
        keyBlobs[ keyID ] = tmp;
        schemeContext->deleteKey(keyID);
    }

    cout << "* Load the generated keys..." << endl;
    // load the keystore with the generated keys
    unique_ptr<OpenABEKeystoreManager> km(new OpenABEKeystoreManager);
    map<string,OpenABEByteString>::iterator it;
    uint64_t expireDate = (uint64_t)time(NULL);
    for(it = keyBlobs.begin(); it != keyBlobs.end(); it++) {
        ASSERT_TRUE(km->storeWithKeyIDCommand(userId, it->first, it->second, expireDate));
    }

    cout << "* Create ciphertext..." << endl;
    // create ciphertext and attempt to find key that decrypts it
    unique_ptr<OpenABEFunctionInput> encInput = getEncInput(input.scheme_type, input.funcInput);
    cout << "Functional Input: " << encInput->toString() << endl;
    schemeContext->encrypt(NULL, MPK, encInput.get(), &plaintext, &ciphertext);

    cout << "* Search for a key..." << endl;
    // attempt decryption
    OpenABEKeyQuery query;
    query.userId = userId;
    query.isEfficient = true; 
    unique_ptr<OpenABEFunctionInput> funcInput = getFunctionInput(&ciphertext);
    const string decKey = km->searchKeyCommand(&query, funcInput.get());
    cout << "The decryption key: " << decKey << endl;
    ASSERT_TRUE(decKey != "");

    cout << "* Decrypt with the key: ";
    pair<string,OpenABEByteString> sk = km->getKeyCommand(userId, decKey);
    skBlob = sk.second;
    ASSERT_TRUE(schemeContext->loadUserSecretParams(decKey, skBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->decrypt(MPK, decKey, &plaintext1, &ciphertext) == OpenABE_NOERROR);
    cout << "success!" << endl;
}

}

INSTANTIATE_TEST_CASE_P(ABETest5, KeystoreManagerTest,
        // arg 1 = scheme type, arg 2 = key input list, arg 3 = enc input string
        ::testing::Values(Config(OpenABE_SCHEME_CP_WATERS, "Alice|Bob:Bob|David:Frank|Eve|Alice|Charlie", "((Alice or Bob) and (Charlie or David))"),
                         Config(OpenABE_SCHEME_KP_GPSW, "((Alice or Charlie) and Eve):(David or Charlie):(Alice and Bob)", "Alice|Bob|Charlie|David")
));

int main(int argc, char **argv) {
  int rc;

  InitializeOpenABE();

  ::testing::InitGoogleTest(&argc, argv);
  rc = RUN_ALL_TESTS();
  ShutdownOpenABE();

  return rc;
}
