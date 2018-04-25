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
///	\file   test_libopenabe.cpp
///
///	\brief  Functional testing utility for OpenABE. This executable is capable
///         of running all functional tests, depending on user settings.
///
///	\author Matthew Green and J. Ayo Akinyele
///

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <assert.h>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <gtest/gtest.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

#define COLOR_STR_GREEN   "\033[32m"
#define COLOR_STR_NORMAL  "\033[0m"
#define COLOR_STR_RED     "\033[31m"

#define EXIT(msg)	cout << msg << endl; goto CLEANUP
#define NUM_PAIRING_TESTS			10
#define ASSERT_RESULT(condition, msg)	if(condition) {	\
	cout << "FAIL: " << msg << endl; \
	return false; }

#define TEST_DESCRIPTION(desc) RecordProperty("description", desc)
#define TESTSUITE_DESCRIPTION(desc) ::testing::Test::RecordProperty("description", desc)

// Global test counters
uint32_t    gNumTests        = 0;
uint32_t    gSuccessfulTests = 0;

//////////
// Utility routines
//////////
namespace {

TEST(libopenabe, PolicyTreeAndAttributeListParser) {
  TEST_DESCRIPTION("policy parser works correctly for supported inputs (and rejects invalid inputs)");

  ASSERT_TRUE(OpenABE_getLibraryVersion() >= 100);

  std::unique_ptr<OpenABEPolicy> policy1 = createPolicyTree("((one or two) and three)");
  ASSERT_TRUE(policy1 != nullptr);

  std::unique_ptr<OpenABEPolicy> policy2 = createPolicyTree("((one > 5 or two) and (three == 15))");
  ASSERT_TRUE(policy2 != nullptr);

  std::unique_ptr<OpenABEPolicy> policy3 = createPolicyTree("((one or two) and (Date > January 1, 2015))");
  ASSERT_TRUE(policy3 != nullptr);

  // test edge cases for attribute lists
  vector<string> attr_list;
  attr_list.push_back("alice");
  attr_list.push_back("bob");
  attr_list.push_back("charlie");
  std::unique_ptr<OpenABEAttributeList> aList;
  ASSERT_ANY_THROW(aList.reset(new OpenABEAttributeList(2, attr_list)));

  std::unique_ptr<OpenABEAttributeList> aList2(new OpenABEAttributeList);

  string test_str1 = "foo:alice", test_str2 = "bar:Date = Jan 1, 2017";
  string compactStr = test_str1 + "|" + test_str2 + "|";
  ASSERT_TRUE(aList2->addAttribute(test_str1));
  ASSERT_TRUE(aList2->addAttribute(test_str2));

  set<string> m_prefix2 = aList2->getPrefixSet();
//  for (auto& d : m_prefix2) {
//    cout << "PREFIX for aList2: " << d << endl;
//  }

  OpenABEByteString result;
  unique_ptr<OpenABEAttributeList> aList3 = createAttributeList(compactStr);
  aList3->serialize(result);

  set<string> m_prefix3 = aList3->getPrefixSet();
//  for (auto& c : m_prefix3) {
//    cout << "PREFIX for aList3: " << c << endl;
//  }

  ASSERT_EQ(aList2->toCompactString(), result.toString());

  ASSERT_TRUE(createAttributeList("") == nullptr);

  ASSERT_TRUE(createAttributeList("|this or that|Value = 30#4") == nullptr);

  cout << "Check if isEqual throws an error correctly" << endl;
  ASSERT_ANY_THROW(aList2->isEqual(nullptr));
}

TEST(libopenabe, BasicPairingTests) {
  TEST_DESCRIPTION("Testing that pairing arithmetic is correct");

  OpenABERNG rng;
  // Create a pairing object
  OpenABEPairing pairing(DEFAULT_BP_PARAM);

  // Generate a random element of G1, G2 and ZP
  G1 eltG1 = pairing.randomG1(&rng);
  G1 anotherEltG1 = pairing.randomG1(&rng);

  //pairing.randomElement(GROUP_G1);
  G2 eltG2 = pairing.randomG2(&rng);
  ZP eltZP = pairing.randomZP(&rng);

  G1 inverseEltG1 = -eltG1;
//		OpenABEElement inverseEltG1 = eltG1;
//        inverseEltG1.multInverse();

  // This makes sure that simple arithmetic on
  // points in G1 works.
  // eltG1 * anotherEltG1 * inv(eltG1) = anotherEltG1
  G1 product = (eltG1 * anotherEltG1);
  G1 undo = (product * inverseEltG1);

  ASSERT_TRUE(undo == anotherEltG1);
}

TEST(libopenabe, PairingArithmeticTests) {
  TEST_DESCRIPTION("Testing that pairing arithmetic is correct");

  OpenABERNG rng;
  // Create a pairing object
  OpenABEPairing pairing(DEFAULT_BP_PARAM);
  G1 eltG1 = pairing.randomG1(&rng);
  G2 eltG2 = pairing.randomG2(&rng);

  // Pairing bilinearity test = NUM_PAIRING_TESTS
  for (int i = 0; i < NUM_PAIRING_TESTS; i++) {
    ZP a = pairing.randomZP(&rng);
    ZP b = pairing.randomZP(&rng);
    ZP c = pairing.randomZP(&rng);
    G1 g1A = eltG1.exp(a);
    G1 g1B = eltG1.exp(b);
    G2 g2A = eltG2.exp(a);
    G2 g2B = eltG2.exp(b);
    GT pairingResult = pairing.pairing(g1A, g2B);
    //cout << "e(eltG1^a, eltG2^b) = " << pairingResult << endl;

    GT pairingResult2 = pairing.pairing(g1B, g2A);
    //cout << "e(eltG1^b, eltG2^a) = " << pairingResult2 << endl;

    ASSERT_TRUE(pairingResult == pairingResult2);

    GT pairingResult3 = pairing.pairing(eltG1, eltG2).exp(a * b);
    ASSERT_TRUE(pairingResult == pairingResult3);

    // working for G1
    G1 g1AB = g1A * g1B;
    G2 g2C = eltG2.exp(c);
    GT pairingResult4 = pairing.pairing(g1AB, g2C);
    GT pairingResult5 = pairing.pairing(g1A, g2C) * pairing.pairing(g1B, g2C);
    ASSERT_TRUE(pairingResult4 == pairingResult5);

    G2 g2BC = eltG2.exp(b) * eltG2.exp(c);
    pairingResult4 = pairing.pairing(g1A, g2BC);
    pairingResult5 = pairing.pairing(g1A, g2B) * pairing.pairing(g1A, g2C);
    ASSERT_TRUE(pairingResult4 == pairingResult5);

    // verify that e(g1^a, g2^b * g2^c) / e(g1^a, g2^c) == e(g1^a, g2^b)
    GT pairingResult6 = pairing.pairing(g1A, g2BC) / pairing.pairing(g1A, g2C);
    ASSERT_TRUE(pairingResult == pairingResult6);
  }
}

TEST(libopenabe, MultiPairings) {
  TEST_DESCRIPTION("Testing that multi-pairing arithmetic is correct");

  OpenABERNG rng;
  // Create a pairing object
  OpenABEPairing pairing(DEFAULT_BP_PARAM);

  vector<G1> g1;
  vector<G2> g2;
  // Generate a random element of G1, G2 and ZP
  G1 p0 = pairing.randomG1(&rng);
  G1 p1 = pairing.randomG1(&rng);
  G2 q0 = pairing.randomG2(&rng);
  G2 q1 = pairing.randomG2(&rng);

  GT gt1 = pairing.pairing(p0, q0) * pairing.pairing(p1, q1);
  // cout << "pairing => " << gt1 << endl;

  g1.push_back(p0);
  g1.push_back(p1);
  g2.push_back(q0);
  g2.push_back(q1);

  GT gt2 = pairing.initGT();
  pairing.multi_pairing(gt2, g1, g2);
  // cout << "pairing prod => " << gt2 << endl;

  ASSERT_TRUE(gt1 == gt2);
}


TEST(libopenabe, MultiPairingsWithMultipleElements) {
  TEST_DESCRIPTION("Testing that multi-pairing arithmetic is correct");
  OpenABERNG rng;
  // Create a pairing object
  OpenABEPairing pairing(DEFAULT_BP_PARAM);

  vector<G1> g1;
  vector<G2> g2;
  G1 p0 = pairing.randomG1(&rng);
  G2 q0 = pairing.randomG2(&rng);

  ZP a = pairing.randomZP(&rng);
  ZP b = pairing.randomZP(&rng);
  ZP c = pairing.randomZP(&rng);
  ZP d = pairing.randomZP(&rng);

  g1.push_back(p0.exp(a));
  g1.push_back(p0.exp(b));

  g2.push_back(q0.exp(c));
  g2.push_back(q0.exp(d));

  // e(g1^a, g2^c) * e(g1^b, g2^d)
  GT gt3 = pairing.pairing(g1.at(0), g2.at(0)) * pairing.pairing(g1.at(1), g2.at(1));

  GT gt4 = pairing.initGT();
  pairing.multi_pairing(gt4, g1, g2);

  ASSERT_TRUE(gt3 == gt4);
}

TEST(libopenabe, LinearSecretSharing) {
  TEST_DESCRIPTION("Test that secret sharing and recovery are consistent");

  // Create a pairing object
  OpenABEPairing pairing(DEFAULT_BP_PARAM);
  // instantiate RNG
  OpenABERNG rng;

  // Create a policy
  // string str = "(Alice and Bob)";
  //string str = "(Alice or Bob)";
  // string str = "((Alice or Bob) and Charlie)";
  //string str = "((Alice or Bob) and (Charlie or David))";
  //string str = "((Alice or Bob) and (Charlie and David))";
  //string str = "((Alice and Bob) and (Charlie or David))";
  //string str = "((Alice and Bob) or (Charlie and David))";
  string str = "((Alice and Bob) and (Charlie and David))"; // fail
  //string str = "(Alice or (Eve and Frank))";
  //string str = "((Eve and Frank) or Alice)";
  //string str = "((Alice and Bob) or Charlie)"; // sort test
  std::unique_ptr<OpenABEPolicy> policy = createPolicyTree(str);
  ASSERT_TRUE(policy != nullptr);
  cout << "Target Policy: " << policy->toString() << endl;

  // Generate a random secret (element of ZP)
  ZP s = pairing.randomZP(&rng);
  cout << "Sharing secret s = " << s << endl;

  // Compute the secret shares
  OpenABELSSS lsss(&pairing, &rng);
  lsss.shareSecret(policy.get(), s);

  // Get the resulting shares
  OpenABELSSSRowMap shares = lsss.getRows();

  cout << "Obtained " << shares.size() << " secret shares" << endl;
  //		for(OpenABELSSSRowMap::const_iterator testIt = shares.begin(); testIt != shares.end(); ++testIt) {
  //			cout << "key: " << testIt->first << ", value: " << testIt->second.element() << endl;
  //		}

  // Next initialize a new LSSS structure and see if we can recover
  // from some basic attribute list
  OpenABELSSS recoveryLsss(&pairing, &rng);
  OpenABEAttributeList attList;
  attList.addAttribute(string("Alice"));
  attList.addAttribute(string("Bob"));
  attList.addAttribute(string("Charlie"));
  attList.addAttribute(string("David"));

  // Failed to recover coefficient! Secret sharing not working.
  ASSERT_TRUE(recoveryLsss.recoverCoefficients(policy.get(), &attList));

  OpenABELSSSRowMap coefficients = recoveryLsss.getRows();
  cout << "Required " << coefficients.size() << " coefficients." << endl;
  // Now use the coefficients to actually recover the secret from
  // shares
  ZP recoveredShare = recoveryLsss.LSSStestSecretRecovery(coefficients, shares);
  cout << "Recovered secret = " << recoveredShare << endl;
  ASSERT_TRUE(recoveredShare == s);

  // Finally, run a test with an invalid attribute list and
  // make sure secret recovery fails. This **should** throw an
  // exception.
  OpenABELSSS recoveryLsss2(&pairing, &rng);
  OpenABEAttributeList attList2;
  attList2.addAttribute(string("Alice"));

  std::unique_ptr<OpenABEPolicy> policy2 = createPolicyTree(str);
  ASSERT_TRUE(policy2 != nullptr);
  ASSERT_FALSE(recoveryLsss2.recoverCoefficients(policy2.get(), &attList2));

  OpenABELSSSRowMap coefficients2 = recoveryLsss2.getRows();
  cout << "Required " << coefficients2.size() << " coefficients." << endl;


  OpenABEPolicy *policy3 = new OpenABEPolicy;
  OpenABETreeNode *left = new OpenABETreeNode("Alice");
  OpenABETreeNode *right = new OpenABETreeNode("Bob");
  OpenABETreeNode *right2 = new OpenABETreeNode("Charlie");

  OpenABETreeNode *m_rootNode = new OpenABETreeNode;
  m_rootNode->setNodeType(GATE_TYPE_THRESHOLD);
  m_rootNode->addSubnode(left);
  m_rootNode->addSubnode(right);
  m_rootNode->addSubnode(right2);

  policy3->setRootNode(m_rootNode);

  // testing more edge cases
  ASSERT_ANY_THROW(recoveryLsss2.recoverCoefficients(policy3, &attList2));
  SAFE_DELETE(policy3);

  OpenABELSSS new_lsss(&pairing, &rng);
  ASSERT_ANY_THROW(new_lsss.shareSecret(nullptr, s));

//	ZP recoveredShare2 = recoveryLsss2.LSSStestSecretRecovery(coefficients2, shares);
//	cout << "Recovered secret = " << recoveredShare2 << endl;
//	ASSERT_TRUE(recoveredShare == s);


//	{
//		// We succeeded in recovering, which means there was a problem with
//		// this test!
//		cout << "Error: recovered coefficients for invalid function input" << endl;
//		return false;
//	}
//
//
//	{
//		cout << "Recovered secret does not match!" << endl;
//		return false;
//	}
}

TEST(libopenabe, Base64Tests) {
  TEST_DESCRIPTION("Testing that Base64 encode/decode works correctly");
  const string to_encode("Hello, world!");
  const string encoded_result("SGVsbG8sIHdvcmxkIQ==");
  const string result = Base64Encode((const unsigned char*)to_encode.data(),
                                      to_encode.size());
  if (encoded_result != result) {
    cout << "Didn't base64 encode to known result! "
         << "(expected: " << encoded_result << " got: " << result << ")"
         << endl;
  }
  ASSERT_TRUE(encoded_result == result);

  if (to_encode != Base64Decode(encoded_result)) {
    cout << "Encode followed by decode of '" << to_encode
         << "' didn't work!" << endl;
  }
  ASSERT_TRUE(to_encode == Base64Decode(encoded_result));

  const string invalid_b64("~");
  EXPECT_THROW(Base64Decode(invalid_b64), OpenABE_ERROR); // OpenABE_ERROR_INVALID_INPUT
}

TEST(libopenabe, SerializationTests) {
  TEST_DESCRIPTION("Testing that pairing group elements serialization works correctly");
  // Create a pairing object
  OpenABEPairing pairing(DEFAULT_BP_PARAM);
  OpenABERNG rng;
  ZP x1, x2;
  pairing.initZP(x2, 0);
  G1 g01 = pairing.initG1(), g10 = pairing.initG1();
  G2 g20 = pairing.initG2(), g21 = pairing.initG2();
  GT gt20 = pairing.initGT(), gt21 = pairing.initGT();
  int trials = 5;

  for(int i = 0; i < trials; i++) {
    cout << "iteration " << i;
    OpenABEByteString byteBlob;
    x1 = pairing.randomZP(&rng);
    x1.serialize(byteBlob);
    //cout << "x1 bytes : " << byteBlob.toHex() << endl;
    //cout << "x1 : " << x1 << endl;

    // deserialize now
    x2.deserialize(byteBlob);
    //cout << "x2 : " << x2 << endl;
    ASSERT_TRUE(x1 == x2);

    // cout << endl << endl;
    g01 = pairing.randomG1(&rng);
    g01.serialize(byteBlob);
    //cout << "G1 : " << byteBlob.toHex() << endl;

    g10.deserialize(byteBlob);
    // cout << "g01: " << g01 << endl;
    // cout << "g10: " << g10 << endl;
    ASSERT_TRUE(g01 == g10);

    OpenABEByteString byteBlob1;
    cout << endl << endl;
    g20 = pairing.randomG2(&rng);
    g20.serialize(byteBlob1);
    // cout << "G2 : " << byteBlob1.toHex() << endl;

    g21.deserialize(byteBlob1);
    //cout << "g20 : " << g20 << endl;
    //cout << "g21 : " << g21 << endl;
    ASSERT_TRUE(g20 == g21);

    OpenABEByteString byteBlob2;
    // cout << endl << endl;
    gt20 = pairing.pairing(g01, g20);
    gt20.serialize(byteBlob2);
    // cout << "GT : " << byteBlob2.toHex() << endl;

    gt21.deserialize(byteBlob2);
    //cout << "gt20 : " << gt20 << endl;
    //cout << "gt21 : " << gt21 << endl;
    ASSERT_TRUE(gt20 == gt21);
  }
}

TEST(libopenabe, SerializationIntTests) {
  TEST_DESCRIPTION("Testing that integer elements serialization works correctly");

  OpenABEByteString byteBlob3;
  OpenABEUInteger ui1(3735928559, 32), ui2(0, 32);
  ui1.serialize(byteBlob3);
  // cout << "ui1 => " << ui1 << endl;
  cout << "32-bit INT: " << byteBlob3.toHex() << endl;
  ui2.deserialize(byteBlob3);
  // cout << "ui2 => " << ui2 << endl;
  ASSERT_TRUE(ui1 == ui2);

  uint64_t val = 144674407370955150;
  OpenABEUInteger ui3(val, 64), ui4(0, 64);
  ui3.serialize(byteBlob3);
  cout << "64-bit INT: " << byteBlob3.toHex() << endl;
  ui4.deserialize(byteBlob3);
  ASSERT_TRUE(ui3 == ui4);
}

TEST(libopenabe, OpenABEByteStringZeroize) {
  TEST_DESCRIPTION("Testing that zeroization for OpenABEByteString works correctly");
  OpenABERNG rng;
  OpenABEByteString buf, empty;

  rng.getRandomBytes(&buf, 100);
  cout << "Rand Bytes: " << buf.toHex() << endl;
  buf.zeroize();

  ASSERT_TRUE(buf.toHex() == empty.toHex());
  ASSERT_TRUE(buf.size() == empty.size());
}

TEST(libopenabe, OpenABECiphertextTests) {
  TEST_DESCRIPTION("Test that ciphertext can support all container object types");

  // Create a pairing object
  OpenABEPairing pairing(DEFAULT_BP_PARAM);
  OpenABERNG rng;
  OpenABECiphertext *ciphertext = new OpenABECiphertext(pairing.getGroup());
  ciphertext->setHeader(OpenABE_NONE_ID, OpenABE_SCHEME_NONE, &rng);

  // create an element of ZP and store/get from ciphertext
  ZP c0 = pairing.randomZP(&rng);
  ciphertext->setComponent("C0", &c0);
  ZP *c1 = ciphertext->getZP("C0");
  ASSERT_TRUE(c0 == *c1);

  G1 g0 = pairing.randomG1(&rng);
  ciphertext->setComponent("G1", &g0);
  G1 *g1 = ciphertext->getG1("G1");
  ASSERT_TRUE(g0 == *g1);

  G2 g2 = pairing.randomG2(&rng);
  ciphertext->setComponent("G2", &g2);
  G2 *g3 = ciphertext->getG2("G2");
  ASSERT_TRUE(g2 == *g3);

  GT gt = pairing.pairing(g0, g2);
  //cout << "gt  : " << gt << endl;
  ciphertext->setComponent("GT", &gt);
  GT *gt0 = ciphertext->getGT("GT");
  ASSERT_TRUE(gt == *gt0);

  string s = "storing this as a test byte string.";
  OpenABEByteString someText;
  someText = s;
  //		cout << "Storing ByteString: '" << someText << "'\n";
  ciphertext->setComponent("str", &someText);
  //		OpenABEByteString *someText2 = ciphertext->getByteString("str");
  //		cout << "Recovered ByteString: '" << *someText2 << "'\n";

  uint32_t integer = 128;
  OpenABEUInteger i(integer);
  //		cout << "Storing integer: " << i << endl;
  ciphertext->setComponent("int", &i);
  OpenABEUInteger *i2 = ciphertext->getInteger("int");
  ASSERT_TRUE(i2->getVal() == i.getVal());
  //        cout << "Recovered integer: " << i2->getVal() << endl;

  vector<string> attributes(3);
  attributes[0] = "Alice";
  attributes[1] = "Bob";
  attributes[2] = "Charlie";
  OpenABEAttributeList *attrlist = new OpenABEAttributeList(3, attributes);
  cout << "<== ATTRIBUTES ==>\n" << *attrlist << "<== ATTRIBUTES ==>\n";
  ciphertext->setComponent("stuff", attrlist);

  OpenABECiphertext *ciphertext2 = new OpenABECiphertext(pairing.getGroup());
  // test serializing the entire ciphertext into a blob (or OpenABEByteString?)
  OpenABEByteString ctBlob;
  ciphertext->exportToBytes(ctBlob);
  //		cout << "<======== CIPHERTEXT ========>\n";
  //		cout << ctBlob << endl;
  //		cout << "<======== CIPHERTEXT ========>\n";

  ciphertext2->loadFromBytes(ctBlob);

  ZP *c11 = ciphertext->getZP("C0");
  ASSERT_TRUE(c0 == *c11);

  G1 *g11 = ciphertext2->getG1("G1");
  ASSERT_TRUE(g0 == *g11);

  G2 *g33 = ciphertext2->getG2("G2");
  ASSERT_TRUE(g2 == *g33);

  GT *gt00 = ciphertext2->getGT("GT");
  // cout << "gt 2: " << gt << endl;
  // cout << "gt00: " << *gt00 << endl;
  ASSERT_TRUE(gt == *gt00);

  OpenABEByteString *someText22 = ciphertext2->getByteString("str");
  cout << "Recovered ByteString: '" << *someText22 << "'\n";

  OpenABEUInteger *i22 = ciphertext2->getInteger("int");
  cout << "Recovered integer: " << i22->getVal() << endl;

  OpenABEAttributeList *attrlist2 = (OpenABEAttributeList*) ciphertext->getComponent("stuff");
  cout << "attrlist2 :\n<== ATTRIBUTES ==>\n" << *attrlist2 << "<== ATTRIBUTES ==>\n";

  ASSERT_TRUE(*ciphertext == *ciphertext2);

  OpenABEByteString uid, emptyUid;
  rng.getRandomBytes(&uid, UID_LEN);

  OpenABECiphertext ct(uid); // random
  OpenABECiphertext ct2(emptyUid); // emtpy (means will be generated internally)
  ASSERT_TRUE(ct.getUID() != ct2.getUID());

  OpenABECiphertext ct3;
  // should be an invalid input (due to less bytes than header size)
  ASSERT_ANY_THROW(ct3.loadFromBytes(uid));

  OpenABEByteString ctBuf;
  ciphertext->getHeader(ctBuf);

  cout << "ctBuf.hex() => " << ctBuf.toHex() << endl;
  ctBuf.insertFirstByte(0x11); // add 1 to header len (16 bytes)
  ctBuf.insertFirstByte(PACK_8);

  ASSERT_ANY_THROW(ct3.loadFromBytes(ctBuf));

  // cleanup
  SAFE_DELETE(ciphertext);
  SAFE_DELETE(ciphertext2);
  SAFE_DELETE(attrlist);
}

TEST(libopenabe, CPATestsForCpAbeKEMContext) {
  TEST_DESCRIPTION("Testing that CPA secure CP-ABE KEM encryption and decryption context is correct");
  OpenABEContextABE *context = NULL;
  OpenABEAttributeList *attrlist = NULL;
  OpenABECiphertext *ciphertext = NULL;
  OpenABESymKeyEnc *aes = NULL, *aes2 = NULL;
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey), newkey(new OpenABESymKey);
  unique_ptr<OpenABERNG> rng(new OpenABERNG);

  // Initialize an RNG
  // Initialize a OpenABEContext structure
  context = OpenABE_createContextABE(&rng, OpenABE_SCHEME_CP_WATERS);
  ASSERT_FALSE(context == NULL);

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(context->generateParams(DEFAULT_BP_PARAM, "testMPK", "testMSK") == OpenABE_NOERROR);


  // Encrypt a test key using the KEM mode
  string s = "((Alice or Bob) and (Charlie or David))";
  std::unique_ptr<OpenABEPolicy> policy = createPolicyTree(s);
  ciphertext = new OpenABECiphertext;
  ASSERT_FALSE(context->encryptKEM(NULL, "testMPK", nullptr, DEFAULT_SYM_KEY_BYTES, symkey, ciphertext) == OpenABE_NOERROR);

  ASSERT_FALSE(context->encryptKEM(NULL, "noSuchMPK", policy.get(), DEFAULT_SYM_KEY_BYTES, symkey, ciphertext) == OpenABE_NOERROR);

  ASSERT_TRUE(context->encryptKEM(NULL, "testMPK", policy.get(), DEFAULT_SYM_KEY_BYTES, symkey, ciphertext) == OpenABE_NOERROR);

  string symKeyStr = symkey->toString();
  cout << "Original symmetric key:  " << symKeyStr << endl;
  aes = new OpenABESymKeyEnc(symKeyStr);
  string data = "0123456789098765 and hello world!";
  string ciphertext2 = aes->encrypt((uint8_t*) data.c_str(), (uint32_t) data.size());
  cout << "successfully encrypted: " << ciphertext2 << endl;

  vector<string> attributes(2);
  attributes[0] = "Alice";
  attributes[1] = "Charlie";
  attrlist = new OpenABEAttributeList(2, attributes);
  cout << "<== ATTRIBUTES ==>\n" << *attrlist << "<== ATTRIBUTES ==>\n";
  ASSERT_TRUE(context->generateDecryptionKey(attrlist, "decKey", "testMPK", "testMSK") == OpenABE_NOERROR);

  ASSERT_FALSE(context->generateDecryptionKey(nullptr, "decKeyBad", "testMPK", "testMSK") == OpenABE_NOERROR);

  ASSERT_FALSE(context->generateDecryptionKey(attrlist, "decKeyBad", "badMPKId", "testMSK") == OpenABE_NOERROR);

  // Decrypt with a bad key
  ASSERT_FALSE(context->decryptKEM("testMPK", "noSuchDecKey", ciphertext, DEFAULT_SYM_KEY_BYTES, newkey) == OpenABE_NOERROR);

  // Decrypt the ciphertext
  ASSERT_TRUE(context->decryptKEM("testMPK", "decKey", ciphertext, DEFAULT_SYM_KEY_BYTES, newkey) == OpenABE_NOERROR);

  string newKeyStr = newkey->toString();
  cout << "Decrypted symmetric key: " << newKeyStr << endl << endl;
  aes2 = new OpenABESymKeyEnc(newKeyStr);
  string plaintext = aes2->decrypt(ciphertext2);
  cout << "Plaintext: " << plaintext << endl;

  ASSERT_TRUE(symKeyStr.compare(newKeyStr.c_str()) == 0);
  ASSERT_TRUE(data.compare(plaintext) == 0);

  SAFE_DELETE(attrlist);
  SAFE_DELETE(ciphertext);
  SAFE_DELETE(aes);
  SAFE_DELETE(aes2);
  SAFE_DELETE(context);
}


TEST(libopenabe, CPATestsForCpAbeSchemeContext) {
  TEST_DESCRIPTION("Testing that CPA secure CP-ABE scheme context is correct");
  unique_ptr<OpenABEContextSchemeCPA> schemeContext = nullptr;
  OpenABEAttributeList *attrlist = NULL;
  OpenABECiphertext *ciphertext = NULL;
  OpenABEByteString mpkBlob, mskBlob;

  // initialize a scheme context with the KEM context
  schemeContext = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(schemeContext->generateParams(DEFAULT_BP_PARAM, "testMPK", "testMSK") == OpenABE_NOERROR);

  ASSERT_TRUE(schemeContext->exportKey("testMPK", mpkBlob) == OpenABE_NOERROR);

  // cout << "MPK: " << mpkBlob.toHex() << "\nlen: " << mpkBlob.size() << endl;

  ASSERT_TRUE(schemeContext->exportKey("testMSK", mskBlob) == OpenABE_NOERROR);

  // cout << "MSK: " << mskBlob.toHex() << "\nlen: " << mskBlob.size() << endl;

  ASSERT_TRUE(schemeContext->deleteKey("testMPK") == OpenABE_NOERROR);
  ASSERT_TRUE(schemeContext->deleteKey("testMSK") == OpenABE_NOERROR);

  ASSERT_TRUE(schemeContext->loadMasterPublicParams("testMPK", mpkBlob) == OpenABE_NOERROR);

  ASSERT_TRUE(schemeContext->loadMasterSecretParams("testMSK", mskBlob) == OpenABE_NOERROR);

  OpenABEByteString plaintext;
  plaintext = "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45\x46";
  string s = "((Alice or Bob) and (Charlie or David))";
  std::unique_ptr<OpenABEPolicy> policy = createPolicyTree(s);
  ciphertext = new OpenABECiphertext;
  ASSERT_TRUE (schemeContext->encrypt(NULL, "testMPK", policy.get(), &plaintext, ciphertext) == OpenABE_NOERROR);

  vector<string> attributes(3);
  attributes[0] = "Alice";
  attributes[1] = "Bob";
  attributes[2] = "Charlie";
  attrlist = new OpenABEAttributeList(3, attributes);
  cout << "<== ATTRIBUTES ==>\n" << *attrlist << "<== ATTRIBUTES ==>\n";
  ASSERT_TRUE(schemeContext->keygen(attrlist, "decKey", "testMPK", "testMSK") == OpenABE_NOERROR);

  // Decrypt the ciphertext
  OpenABEByteString plaintext2;
  ASSERT_TRUE(schemeContext->decrypt("testMPK", "decKey", &plaintext2, ciphertext) == OpenABE_NOERROR);

  cout << "Orig M: " << plaintext.toHex() << endl;
  cout << "Recv M: " << plaintext2.toHex() << endl;
  ASSERT_TRUE(plaintext.toHex() == plaintext2.toHex());

  SAFE_DELETE(ciphertext);
  SAFE_DELETE(attrlist);
}

TEST(libopenabe, CPATestsForKpAbeSchemeContext) {
  TEST_DESCRIPTION("Testing that CPA secure KP-ABE scheme context is correct");
  unique_ptr<OpenABEContextSchemeCPA> schemeContext = nullptr;
  OpenABEAttributeList *attrlist = NULL;
  OpenABECiphertext *ciphertext = NULL;
  OpenABEByteString mpkBlob, mskBlob;

  // initialize a scheme context with the KEM context
  schemeContext = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_KP_GPSW);

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(schemeContext->generateParams(DEFAULT_BP_PARAM, "testMPK", "testMSK") == OpenABE_NOERROR);

  ASSERT_TRUE(schemeContext->exportKey("testMPK", mpkBlob) == OpenABE_NOERROR);

  // cout << "MPK: " << mpkBlob.toHex() << "\nlen: " << mpkBlob.size() << endl;

  ASSERT_TRUE(schemeContext->exportKey("testMSK", mskBlob) == OpenABE_NOERROR);

  // cout << "MSK: " << mskBlob.toHex() << "\nlen: " << mskBlob.size() << endl;

  ASSERT_TRUE(schemeContext->deleteKey("testMPK") == OpenABE_NOERROR);
  ASSERT_TRUE(schemeContext->deleteKey("testMSK") == OpenABE_NOERROR);

  ASSERT_TRUE(schemeContext->loadMasterPublicParams("testMPK", mpkBlob) == OpenABE_NOERROR);

  ASSERT_TRUE(schemeContext->loadMasterSecretParams("testMSK", mskBlob) == OpenABE_NOERROR);

  OpenABEByteString plaintext;
  plaintext = "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45\x46";
  vector<string> attributes(3);
  attributes[0] = "Alice";
  attributes[1] = "Bob";
  attributes[2] = "Charlie";
  attrlist = new OpenABEAttributeList(3, attributes);
  cout << "<== ATTRIBUTES ==>\n" << *attrlist << "<== ATTRIBUTES ==>\n";
  ciphertext = new OpenABECiphertext;

  ASSERT_TRUE(schemeContext->encrypt(NULL, "testMPK", attrlist, &plaintext, ciphertext) == OpenABE_NOERROR);

  string s = "((Alice or Bob) and (Charlie or David))";
  std::unique_ptr<OpenABEPolicy> policy = createPolicyTree(s);
  ASSERT_TRUE(schemeContext->keygen(policy.get(), "decKey", "testMPK", "testMSK") == OpenABE_NOERROR);

  // Decrypt the ciphertext
  OpenABEByteString plaintext2;
  ASSERT_TRUE(schemeContext->decrypt("testMPK", "decKey", &plaintext2, ciphertext) == OpenABE_NOERROR);

  cout << "Orig M: " << plaintext.toHex() << endl;
  cout << "Recv M: " << plaintext2.toHex() << endl;
  ASSERT_TRUE(plaintext.toHex() == plaintext2.toHex());

  SAFE_DELETE(ciphertext);
  SAFE_DELETE(attrlist);
}

TEST(libopenabe, CCATestsForCpAbeKEMContext) {
  TEST_DESCRIPTION("Testing that CCA secure CP-ABE KEM context (wrapper around CPA KEM) is correct");

  unique_ptr<OpenABEContextSchemeCPA> schemeContext = nullptr;
  OpenABEContextCCA *contextCCAKEM = NULL;
  OpenABECiphertext *ciphertext = NULL;
  OpenABEAttributeList *attrlist = NULL;
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey), newkey(new OpenABESymKey);
  // Initialize an RNG
  unique_ptr<OpenABERNG> rng(new OpenABERNG);

  // initialize a scheme context with the KEM context
  schemeContext = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);

  // initialize a CCA scheme context
  contextCCAKEM = (OpenABEContextCCA*) new OpenABEContextGenericCCA(std::move(schemeContext));
  ASSERT_FALSE(contextCCAKEM == NULL);

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(contextCCAKEM->generateParams(DEFAULT_BP_PARAM, "testMPK", "testMSK") == OpenABE_NOERROR);

  // should return false
  ASSERT_FALSE(contextCCAKEM->generateParams(DEFAULT_BP_PARAM, "testMPK", "testMSK") == OpenABE_NOERROR);

  // Encrypt a test key using the KEM mode
  string s = "((Alice or Bob) and (Charlie or David))";
  std::unique_ptr<OpenABEPolicy> policy = createPolicyTree(s);
  ciphertext = new OpenABECiphertext;
  ASSERT_FALSE(contextCCAKEM->encryptKEM(rng.get(), "testMPK", nullptr, DEFAULT_SYM_KEY_BYTES, symkey, ciphertext) == OpenABE_NOERROR);
  ASSERT_FALSE(contextCCAKEM->encryptKEM(rng.get(), "noSuchMPK", policy.get(), DEFAULT_SYM_KEY_BYTES, symkey, ciphertext) == OpenABE_NOERROR);

  ASSERT_TRUE(contextCCAKEM->encryptKEM(rng.get(), "testMPK", policy.get(), DEFAULT_SYM_KEY_BYTES, symkey, ciphertext) == OpenABE_NOERROR);

  const string symkeyStr = symkey->toString();
  cout << "Orig symmetric key:  " << symkeyStr << endl;

  // generate a decryption key
  vector<string> attributes(3);
  attributes[0] = "Alice";
  attributes[1] = "Bob";
  attributes[2] = "Charlie";
  attrlist = new OpenABEAttributeList(attributes.size(), attributes);
  cout << "<== ATTRIBUTES ==>\n" << *attrlist << "<== ATTRIBUTES ==>\n";
  ASSERT_TRUE(contextCCAKEM->generateDecryptionKey(attrlist, "decKey", "testMPK", "testMSK") == OpenABE_NOERROR);

  // Decrypt the ciphertext
  ASSERT_TRUE(contextCCAKEM->decryptKEM("testMPK", "decKey", ciphertext, DEFAULT_SYM_KEY_BYTES, newkey) == OpenABE_NOERROR);

  const string newkeyStr = newkey->toString();
  cout << "Recv symmetric key:  " << newkeyStr << endl;
  ASSERT_TRUE(symkeyStr.compare(newkeyStr) == 0);

  SAFE_DELETE(attrlist);
  SAFE_DELETE(ciphertext);
  SAFE_DELETE(contextCCAKEM);
}

TEST(libopenabe, CCATestsForCpAbeSchemeContext) {
  TEST_DESCRIPTION("Testing that CCA secure CP-ABE Scheme context (wrapper around CCA KEM) is correct");
  OpenABECiphertext *ciphertext1 = nullptr, *ciphertext2 = nullptr;
  OpenABEAttributeList *attrlist = nullptr;
  string plaintext1, plaintext2;
  // Initialize an RNG

  // initialize a scheme context with the KEM context
  unique_ptr<OpenABEContextSchemeCCA> ccaSchemeContext = OpenABE_createContextABESchemeCCA(OpenABE_SCHEME_CP_WATERS);

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(ccaSchemeContext->generateParams(DEFAULT_BP_PARAM, "testMPK", "testMSK") == OpenABE_NOERROR);

  // Encrypt a test key using the KEM mode
  std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("((Alice or Bob) and (Charlie or David))");
  plaintext1 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  ciphertext1 = new OpenABECiphertext;
  ciphertext2 = new OpenABECiphertext;
  ASSERT_TRUE(ccaSchemeContext->encrypt("testMPK", policy.get(), plaintext1, ciphertext1, ciphertext2) == OpenABE_NOERROR);

  vector<string> attributes;
  attributes.push_back("Alice");
  attributes.push_back("Bob");
  attributes.push_back("Charlie");
  attrlist = new OpenABEAttributeList(attributes.size(), attributes);
  cout << "<== ATTRIBUTES ==>\n" << *attrlist << "<== ATTRIBUTES ==>\n";
  ASSERT_TRUE(ccaSchemeContext->keygen(attrlist, "decKey", "testMPK", "testMSK") == OpenABE_NOERROR);

  // Decrypt the ciphertext
  ASSERT_TRUE(ccaSchemeContext->decrypt("testMPK", "decKey", plaintext2, ciphertext1, ciphertext2) == OpenABE_NOERROR);

  cout << "Orig M: " << plaintext1 << endl;
  cout << "Recv M: " << plaintext2 << endl;
  ASSERT_TRUE(plaintext1.compare(plaintext2) == 0);

  SAFE_DELETE(ciphertext1);
  SAFE_DELETE(ciphertext2);
  SAFE_DELETE(attrlist);
}

TEST(libopenabe, CCATestsForKpAbeSchemeContextWithATZN) {
  TEST_DESCRIPTION("Testing that CCA secure KP-ABE Scheme context with amortization (wrapper around CCA KEM) is correct");
  OpenABECiphertext *ciphertext = nullptr;
  string key1, key2;
  string plaintext1, plaintext2, ciphertext1, ciphertext2;
  OpenABEByteString out1, out2;

  // initialize a scheme context with the KEM context
  unique_ptr<OpenABEContextSchemeCCAWithATZN> ccaKpabe = OpenABE_createContextABESchemeCCAWithATZN(OpenABE_SCHEME_KP_GPSW);

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(ccaKpabe->generateParams(DEFAULT_BP_PARAM, "testMPK", "testMSK") == OpenABE_NOERROR);

  // Encrypt a test key using the KEM mode
  std::unique_ptr<OpenABEAttributeList> attrlist = createAttributeList("Alice|Bob|Charlie");
  ciphertext = new OpenABECiphertext;
  unique_ptr<OpenABESymKeyHandle> keyHandle1 = ccaKpabe->encrypt("testMPK", attrlist.get(), ciphertext);

  // encrypt plaintext files using handle
  plaintext1 = "hello world this is message 1 under same enc input.";
  keyHandle1->encrypt(ciphertext1, plaintext1);
  out1 = ciphertext1;
  cout << "Ciphertext 1: " << out1.toHex() << " => " << ciphertext1.size() << " bytes" << endl;

  plaintext2 = "hello world this is message 2 under same enc input.";
  keyHandle1->encrypt(ciphertext2, plaintext2);
  out2 = ciphertext2;
  cout << "Ciphertext 2: " << out2.toHex() << " => " << ciphertext2.size() << " bytes" << endl;
  ASSERT_TRUE(out1 != out2);

  // Generate the decryption key
  std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("((Alice or Bob) and (Charlie or David))");
  cout << "<== POLICY ==>\n" << *policy << "\n<== POLICY ==>\n";
  ASSERT_TRUE(ccaKpabe->keygen(policy.get(), "decKey", "testMPK", "testMSK") == OpenABE_NOERROR);

  // Decrypt the ciphertext
  unique_ptr<OpenABESymKeyHandle> keyHandle2 = ccaKpabe->decrypt("testMPK", "decKey", ciphertext);
  ASSERT_TRUE(keyHandle2 != nullptr);

  keyHandle1->exportKey(key1);
  keyHandle2->exportKey(key2);

  out1 = key1;
  out2 = key2;

  cout << "Orig K: " << out1.toHex() << endl;
  cout << "Recv K: " << out2.toHex() << endl;
  ASSERT_TRUE(key1.compare(key2) == 0);

  string pt1, pt2;
  keyHandle2->decrypt(pt2, ciphertext2);
  keyHandle2->decrypt(pt1, ciphertext1);
  ASSERT_TRUE(plaintext1.compare(pt1) == 0);
  ASSERT_TRUE(plaintext2.compare(pt2) == 0);
  cout << "Rec M1: " << pt1 << endl;
  cout << "Rec M2: " << pt2 << endl;

  SAFE_DELETE(ciphertext);
}


TEST(libopenabe, CPATestsForKpAbeKEMContext) {
  TEST_DESCRIPTION("Testing that CPA secure KP-ABE KEM encryption and decryption context is correct");

  OpenABEContextABE *context = NULL;
  OpenABEAttributeList *attrlist = NULL;
  OpenABECiphertext *ciphertext = NULL;
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey), newkey(new OpenABESymKey);
  // Initialize an RNG
  unique_ptr<OpenABERNG> rng(new OpenABERNG);

  // Initialize a OpenABEContext structure
  context = OpenABE_createContextABE(&rng, OpenABE_SCHEME_KP_GPSW);

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(context->generateParams(DEFAULT_BP_PARAM, "testMPK", "testMSK") == OpenABE_NOERROR);

  // can't generate params for an existing ID
  ASSERT_TRUE(context->generateParams(DEFAULT_BP_PARAM, "testMPK", "testMSK") == OpenABE_ERROR_INVALID_PARAMS_ID);

  vector<string> attributes(3);
  attributes[0] = "Alice";
  attributes[1] = "Bob";
  attributes[2] = "Charlie";
  attrlist = new OpenABEAttributeList(attributes.size(), attributes);
  cout << "<== ATTRIBUTES ==>\n" << *attrlist << "<== ATTRIBUTES ==>\n";

  ciphertext = new OpenABECiphertext;
  ASSERT_TRUE(context->encryptKEM(NULL, "testMPK", nullptr, DEFAULT_SYM_KEY_BYTES, symkey, ciphertext) == OpenABE_ERROR_INVALID_INPUT);
  ASSERT_TRUE(context->encryptKEM(NULL, "noSuchMPK", attrlist, DEFAULT_SYM_KEY_BYTES, symkey, ciphertext) == OpenABE_ERROR_INVALID_PARAMS);

  ASSERT_TRUE(context->encryptKEM(NULL, "testMPK", attrlist, DEFAULT_SYM_KEY_BYTES, symkey, ciphertext) == OpenABE_NOERROR);

  string symKeyStr = symkey->toString();
  cout << "Original symmetric key:  " << symKeyStr << endl;

  string s = "((Alice or Bob) and (Charlie or David))";
  cout << "Decryption key policy: " << s << endl;
  std::unique_ptr<OpenABEPolicy> policy = createPolicyTree(s);
  // fail
  ASSERT_TRUE(context->generateDecryptionKey(nullptr, "decKey", "testMPK", "testMSK") == OpenABE_ERROR_INVALID_INPUT);
  // fail
  ASSERT_TRUE(context->generateDecryptionKey(policy.get(), "decKey", "noSuchMPK", "testMSK") == OpenABE_ERROR_INVALID_PARAMS);

  ASSERT_TRUE(context->generateDecryptionKey(policy.get(), "decKey", "testMPK", "testMSK") == OpenABE_NOERROR);

  // Decrypt the ciphertext
  ASSERT_TRUE(context->decryptKEM("testMPK", "decKey", ciphertext, DEFAULT_SYM_KEY_BYTES, newkey) == OpenABE_NOERROR);

  string newKeyStr = newkey->toString();
  cout << "Decrypted symmetric key: " << newKeyStr << endl << endl;

  SAFE_DELETE(attrlist);
  SAFE_DELETE(ciphertext);
  SAFE_DELETE(context);
}

TEST(libopenabe, CCATestsForKpAbeKEMContext) {
  TEST_DESCRIPTION("Testing that CCA secure KP-ABE KEM context (wrapper around CPA KEM) is correct");
  unique_ptr<OpenABEContextSchemeCPA> schemeContext = nullptr;
  OpenABEContextCCA *contextCCAKEM = NULL;
  OpenABEAttributeList *attrlist = NULL;
  OpenABECiphertext *ciphertext = NULL;
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey), newkey(new OpenABESymKey);
  // Initialize an RNG
  unique_ptr<OpenABERNG> rng(new OpenABERNG);
  unique_ptr<OpenABERNG> rng2(new OpenABERNG);

  // initialize a scheme context with the KEM context
  schemeContext = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_KP_GPSW);

  // initialize a CCA scheme context
  contextCCAKEM = (OpenABEContextCCA*) new OpenABEContextGenericCCA(std::move(schemeContext));

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(contextCCAKEM->generateParams(DEFAULT_BP_PARAM, "testMPK", "testMSK") == OpenABE_NOERROR);

  // Encrypt a test key using the KEM mode
  vector<string> attributes(3);
  attributes[0] = "Alice";
  attributes[1] = "Bob";
  attributes[2] = "Charlie";
  attrlist = new OpenABEAttributeList(attributes.size(), attributes);
  cout << "<== ATTRIBUTES ==>\n" << *attrlist << "<== ATTRIBUTES ==>\n";
  ciphertext = new OpenABECiphertext;
  ASSERT_TRUE(contextCCAKEM->encryptKEM(rng2.get(), "testMPK", attrlist, DEFAULT_SYM_KEY_BYTES, symkey, ciphertext) == OpenABE_NOERROR);
  const string symkeyStr = symkey->toString();
  cout << "Orig symmetric key:  " << symkeyStr << endl;

  // generate a decryption key
  string s = "((Alice or Bob) and (Charlie or David))";
  std::unique_ptr<OpenABEPolicy> policy = createPolicyTree(s);
  ASSERT_TRUE(contextCCAKEM->generateDecryptionKey(policy.get(), "decKey", "testMPK", "testMSK") == OpenABE_NOERROR);

  // Decrypt the ciphertext
  ASSERT_TRUE(contextCCAKEM->decryptKEM("testMPK", "decKey", ciphertext, DEFAULT_SYM_KEY_BYTES, newkey) == OpenABE_NOERROR);

  const string newkeyStr = newkey->toString();
  cout << "Recv symmetric key:  " << newkeyStr << endl;
  ASSERT_TRUE(newkeyStr.compare(symkeyStr) == 0);

  SAFE_DELETE(attrlist);
  SAFE_DELETE(ciphertext);
  SAFE_DELETE(contextCCAKEM);
}


TEST(libopenabe, CSPRNG) {
  TEST_DESCRIPTION("CSPRNG using AES-CTR-128 encryption");
  OpenABERNG *rng = NULL, *csprng1 = NULL, *csprng2 = NULL;
  uint8_t buf[SHA256_LEN+1];

  rng = new OpenABERNG;

  rng->getRandomBytes(buf, SHA256_LEN);
  cout << "OpenSSL RNG test:\n";
  BIO_dump_fp(stdout, (const char *) buf, SHA256_LEN);
  cout << endl;
  rng->getRandomBytes(buf, SHA256_LEN);
  BIO_dump_fp(stdout, (const char *) buf, SHA256_LEN);
  cout << endl;


  cout << "OpenSSL PRNG test:\n";
  OpenABEPairing pairing(DEFAULT_BP_PARAM);

  uint32_t length = 64;
  ZP x = pairing.randomZP(rng);
  size_t byte_len = SHA256_LEN; 

  cout << "x : " << x << endl;
  OpenABEByteString xBin = x.getByteString();
  cout << "xBin : " << xBin.toHex() << endl;
  cout << "xBin size : " << xBin.size() << endl;
  if (xBin.size() < byte_len) {
  size_t x_size = xBin.size();
  for(size_t i = 0; i < (byte_len - x_size); i++)
    xBin.insertFirstByte(0x00);
  }
  ASSERT_TRUE(xBin.size() == byte_len);

  OpenABEByteString seed = pairing.hashFromBytes(xBin, length, 0x00);
  cout << "seed : " << seed.toHex() << endl;

  SAFE_DELETE(rng);

  csprng1 = (OpenABERNG*)new OpenABECTR_DRBG(xBin);
  csprng1->setSeed(seed);

  OpenABEByteString x1;
  csprng1->getRandomBytes(&x1, length);
  cout << "x1: " << x1.toHex() << endl;
  cout << "x1 size: " << x1.size() << endl;

  csprng2 = (OpenABERNG*)new OpenABECTR_DRBG(xBin);
  csprng2->setSeed(seed);

  OpenABEByteString x2;
  csprng2->getRandomBytes(&x2, length);
  cout << "x2: " << x2.toHex() << endl;
  cout << "x2 size: " << x2.size() << endl;
  ASSERT_TRUE(x1.size() == x2.size());

  // XOR tests
  OpenABEByteString lhs;
  csprng1->getRandomBytes(&lhs, length);

  OpenABEByteString rhs;
  csprng1->getRandomBytes(&rhs, length);

  ASSERT_TRUE(lhs.size() == rhs.size());

  cout << "\nTesting XOR with random OpenABEByteString objects...\n";
  cout << "lhs: 0x" << lhs.toHex() << endl;

  cout << "rhs: 0x" << rhs.toHex() << endl;

  lhs ^= rhs;

  cout << "\nresult: 0x" << lhs.toHex() << endl;

  SAFE_DELETE(csprng1);
  SAFE_DELETE(csprng2);

  // test KDF
  OpenABEKDF *kdf = new OpenABEKDF;
  OpenABEByteString key = kdf->DeriveKey(lhs, 256, rhs);
  cout << "Derived Key: " << key.toHex() << endl;
  SAFE_DELETE(kdf);
  ASSERT_TRUE(key.size() == SHA256_LEN);

}

static size_t offset;
static int self_test_entropy_callback(void *data, uint8_t *buf, size_t len) {
    const uint8_t *p = (uint8_t *)data;
    memcpy(buf, p + offset, len);
    offset += len;
    return 0;
}

bool CTR_DRBG_NIST_Test(int count, const uint8_t *entropy_source_nopr,
                        const uint8_t *nonce_pers_nopr, const uint8_t *result_nopr) {
  OpenABECtrDrbgContext drbg(entropy_source_nopr, 64);
  uint8_t buf[16];
  memset(buf, 0, 16);

  offset = 0;
  drbg.initSeed(self_test_entropy_callback, nonce_pers_nopr, 16);
  drbg.getRandomBytes(buf, 16);
  drbg.reSeed(NULL, 0);
  drbg.getRandomBytes(buf, 16);

  cout << "Test Vector " << to_string(count) << ": ";
  if (memcmp(buf, result_nopr, 16) == 0) {
    cout << "PASSED" << endl;
    return true;
  } else {
    cerr << "FAILED: did not get expected drbg output!" << endl;
    return false;
  }
}

TEST(libopenabe, CTR_DRBG) {
  TEST_DESCRIPTION("Testing that CTR_DRBG is implemented correctly (via test vectors)");
//    uint8_t pt[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,
//                    0x00,0x00,0x00,0x00,0x00,0x00,
//                    0x00,0x00,0x00};
//    size_t len = 16;
//    uint8_t ct0[len];

//        // test 1
//        memset(ct0, 0, len);
//        uint8_t key1[] = {0xc4,0x7b,0x02,0x94,0xdb,0xbb,0xee,
//                         0x0f,0xec,0x47,0x57,0xf2,0x2f,
//                         0xfe,0xee,0x35,0x87,0xca,0x47,
//                         0x30,0xc3,0xd3,0x3b,0x69,0x1d,
//                         0xf3,0x8b,0xab,0x07,0x6b,0xc5,0x58};
//        uint8_t ct1[] = {0x46,0xf2,0xfb,0x34,0x2d,0x6f,0x0a,
//                        0xb4,0x77,0x47,0x6f,0xc5,0x01,
//                        0x24,0x2c,0x5f};
//
//        // by default AES-256 ECB
//        AES_ECB(key1, pt, ct0, len);
//        cout << "ECB Test 0: ";
//        if (memcmp(ct0, ct1, len) == 0) {
//            cout << "PASSED" << endl;
//        } else {
//            cerr << "FAILED: Ciphertexts do not match test vector!" << endl;
//        }
//
//        // test 2
//        memset(ct0, 0, len);
//        uint8_t key2[] = {0x28,0xd4,0x6c,0xff,0xa1,0x58,0x53,
//                          0x31,0x94,0x21,0x4a,0x91,0xe7,
//                          0x12,0xfc,0x2b,0x45,0xb5,0x18,
//                          0x07,0x66,0x75,0xaf,0xfd,0x91,
//                          0x0e,0xde,0xca,0x5f,0x41,0xac,0x64};
//        uint8_t ct2[] = {0x4b,0xf3,0xb0,0xa6,0x9a,0xeb,0x66,
//                         0x57,0x79,0x4f,0x29,0x01,0xb1,
//                         0x44,0x0a,0xd4};
//
//        // by default AES-256 ECB
//        AES_ECB(key2, pt, ct0, len);
//        cout << "ECB Test 1: ";
//        if (memcmp(ct0, ct2, len) == 0) {
//            cout << "PASSED" << endl;
//        } else {
//            cerr << "FAILED: Ciphertexts do not match test vector!" << endl;
//        }

  // AES-256 use df (from CTR_DRBG_nopr_false)
  // Count 0
  const uint8_t entropy0_source_nopr[64] =
    { 0x5a, 0x19, 0x4d, 0x5e, 0x2b, 0x31, 0x58,
     0x14, 0x54, 0xde, 0xf6, 0x75, 0xfb,
     0x79, 0x58, 0xfe, 0xc7, 0xdb, 0x87,
     0x3e, 0x56, 0x89, 0xfc, 0x9d, 0x03,
     0x21, 0x7c, 0x68, 0xd8, 0x03, 0x38,
     0x20, 0xf9, 0xe6, 0x5e, 0x04, 0xd8,
     0x56, 0xf3, 0xa9, 0xc4, 0x4a, 0x4c,
     0xbd, 0xc1, 0xd0, 0x08, 0x46, 0xf5,
     0x98, 0x3d, 0x77, 0x1c, 0x1b, 0x13,
     0x7e, 0x4e, 0x0f, 0x9d, 0x8e, 0xf4,
     0x09, 0xf9, 0x2e };

  const uint8_t nonce0_pers_nopr[16] =
    { 0x1b, 0x54, 0xb8, 0xff, 0x06, 0x42, 0xbf,
     0xf5, 0x21, 0xf1, 0x5c, 0x1c, 0x0b,
     0x66, 0x5f, 0x3f };

  const uint8_t result0_nopr[16] =
    { 0xa0, 0x54, 0x30, 0x3d, 0x8a, 0x7e, 0xa9,
     0x88, 0x9d, 0x90, 0x3e, 0x07, 0x7c,
     0x6f, 0x21, 0x8f };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(0, entropy0_source_nopr, nonce0_pers_nopr, result0_nopr));

  // Count 1
  const uint8_t entropy1_source_nopr[64] =
    { 0x93, 0xb7, 0x05, 0x5d, 0x78, 0x88, 0xae,
     0x23, 0x4b, 0xfb, 0x43, 0x1e, 0x37,
     0x90, 0x69, 0xd0, 0x0a, 0xe8, 0x10,
     0xfb, 0xd4, 0x8f, 0x2e, 0x06, 0xc2,
     0x04, 0xbe, 0xae, 0x3b, 0x0b, 0xfa,
     0xf0, 0x91, 0xd1, 0xd0, 0xe8, 0x53,
     0x52, 0x5e, 0xad, 0x0e, 0x7f, 0x79,
     0xab, 0xb0, 0xf0, 0xbf, 0x68, 0x06,
     0x45, 0x76, 0x33, 0x9c, 0x35, 0x85,
     0xcf, 0xd6, 0xd9, 0xb5, 0x5d, 0x4f,
     0x39, 0x27, 0x8d };

  const uint8_t nonce1_pers_nopr[16] =
    { 0x90, 0xbc, 0x3b, 0x55, 0x5b, 0x9d, 0x6b,
     0x6a, 0xeb, 0x17, 0x74, 0xa5, 0x83,
     0xf9, 0x8c, 0xad };

  const uint8_t result1_nopr[16] =
    { 0xaa, 0xf2, 0x7f, 0xc2, 0xbf, 0x64, 0xb0,
     0x32, 0x0d, 0xd3, 0x56, 0x4b, 0xb9,
     0xb0, 0x33, 0x77 };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(1, entropy1_source_nopr, nonce1_pers_nopr, result1_nopr));

  // Count 2
  const uint8_t entropy2_source_nopr[64] =
    { 0x58, 0x36, 0x4c, 0xee, 0xfa, 0xd3, 0x75,
     0x81, 0xc5, 0x18, 0xb7, 0xd4, 0x2a,
     0xc4, 0xf9, 0xaa, 0xe2, 0x2b, 0xef,
     0xd8, 0x4c, 0xbc, 0x98, 0x6c, 0x08,
     0xd1, 0xfb, 0x20, 0xd3, 0xbd, 0x24,
     0x00, 0xa8, 0x99, 0xba, 0xfd, 0x47,
     0x02, 0x78, 0xfa, 0xd8, 0xf0, 0xa5,
     0x0f, 0x84, 0x90, 0xaf, 0x29, 0xf9,
     0x38, 0x47, 0x1b, 0x40, 0x75, 0x65,
     0x4f, 0xda, 0x57, 0x7d, 0xad, 0x20,
     0xfa, 0x01, 0xca };

  const uint8_t nonce2_pers_nopr[16] =
    { 0x4a, 0x2a, 0x7d, 0xcb, 0xde, 0x58, 0xb8,
     0xb3, 0xc3, 0xf4, 0x69, 0x7b, 0xeb,
     0x67, 0xbb, 0xa2 };

  const uint8_t result2_nopr[16] =
    { 0x20, 0xc5, 0x11, 0x7a, 0x8a, 0xca, 0x72,
     0xee, 0x5a, 0xb9, 0x14, 0x68, 0xda,
     0xf4, 0x4f, 0x29 };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(2, entropy2_source_nopr, nonce2_pers_nopr, result2_nopr));

  // Count 3
  const uint8_t entropy3_source_nopr[64] =
    { 0x2f, 0x04, 0x4b, 0x86, 0x51, 0xe1, 0xc9,
     0xd9, 0x93, 0x17, 0x08, 0x4c, 0xc6,
     0xc4, 0xfa, 0x1f, 0x50, 0x2d, 0xd6,
     0x24, 0x66, 0xa5, 0x7d, 0x4b, 0x88,
     0xbc, 0x0d, 0x70, 0x3c, 0xab, 0xc5,
     0x62, 0x70, 0x82, 0x01, 0xac, 0x19,
     0xcd, 0xb5, 0xcf, 0x91, 0x8f, 0xae,
     0x29, 0xc0, 0x09, 0xfb, 0x1a, 0x2c,
     0xf4, 0x2f, 0xd7, 0x14, 0xcc, 0x9a,
     0x53, 0xca, 0x5a, 0xcb, 0x71, 0x54,
     0x82, 0x45, 0x6a };

  const uint8_t nonce3_pers_nopr[16] =
    { 0x91, 0x1f, 0xaa, 0xb1, 0x34, 0x7a, 0xe2,
     0xb3, 0x09, 0x3a, 0x60, 0x7c, 0x8b,
     0xc7, 0x7b, 0xfe };

  const uint8_t result3_nopr[16] =
    { 0xaa, 0xe0, 0xc0, 0xac, 0x97, 0xf5, 0x3d,
     0x22, 0x2b, 0x83, 0x57, 0x8a, 0x2b,
     0x3d, 0xd0, 0x5d };

  CTR_DRBG_NIST_Test(3, entropy3_source_nopr, nonce3_pers_nopr, result3_nopr);

  // Count 4
  const uint8_t entropy4_source_nopr[64] =
    { 0x77, 0xd0, 0xf0, 0xef, 0xbc, 0x7c, 0xa7,
     0x94, 0xa5, 0x1d, 0xff, 0x96, 0xe8,
     0x5b, 0x8e, 0x7d, 0xfd, 0x48, 0x75,
     0xfb, 0xfb, 0x6e, 0x55, 0x93, 0xae,
     0x17, 0x90, 0x8b, 0xfb, 0xdd, 0xc3,
     0x13, 0xe0, 0x51, 0xcb, 0x7d, 0x65,
     0x9c, 0x83, 0x81, 0x80, 0xd8, 0x34,
     0xfd, 0xd9, 0x87, 0xae, 0x3c, 0x7f,
     0x60, 0x5a, 0xaa, 0x1b, 0x3a, 0x93,
     0x65, 0x75, 0x38, 0x4b, 0x00, 0x2a,
     0x35, 0xdd, 0x98 };

  const uint8_t nonce4_pers_nopr[16] =
    { 0xf9, 0x59, 0xf1, 0xbc, 0x10, 0x0a, 0xe3,
     0x00, 0x88, 0x01, 0x7f, 0xae, 0x51,
     0x28, 0x9d, 0x8e };

  const uint8_t result4_nopr[16] =
    { 0x5d, 0x80, 0xbc, 0x3f, 0xff, 0xa4, 0x2b,
     0x89, 0xcc, 0xb3, 0x90, 0xe8, 0x44,
     0x7e, 0x33, 0xe5 };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(4, entropy4_source_nopr, nonce4_pers_nopr, result4_nopr));

  // Count 5
  const uint8_t entropy5_source_nopr[64] =
    { 0x6b, 0xb1, 0x4d, 0xc3, 0x4f, 0x66, 0x97,
     0x59, 0xf8, 0xfa, 0x54, 0x53, 0xc4,
     0x89, 0x9e, 0xb5, 0xac, 0x4e, 0x33,
     0xa6, 0x9e, 0x35, 0xe8, 0x9b, 0x19,
     0xa4, 0x6d, 0xbd, 0x08, 0x88, 0x42,
     0x9d, 0x13, 0x67, 0xf7, 0xf3, 0x19,
     0x1e, 0x91, 0x1b, 0x3b, 0x35, 0x5b,
     0x6e, 0x3b, 0x24, 0x26, 0xe2, 0x42,
     0xef, 0x41, 0x40, 0xdd, 0xcc, 0x96,
     0x76, 0x37, 0x11, 0x01, 0x20, 0x96,
     0x62, 0xf2, 0x53 };

  const uint8_t nonce5_pers_nopr[16] =
    { 0x45, 0xa8, 0xbb, 0x33, 0x06, 0x27, 0x83,
     0xee, 0xde, 0x09, 0xb0, 0x5a, 0x35,
     0xbd, 0x44, 0xdd };

  const uint8_t result5_nopr[16] =
    { 0x0d, 0xfa, 0x99, 0x55, 0xa1, 0x3a, 0x9c,
     0x57, 0xa3, 0x54, 0x6a, 0x04, 0x10,
     0x8b, 0x8e, 0x9e };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(5, entropy5_source_nopr, nonce5_pers_nopr, result5_nopr));

  // Count 6
  const uint8_t entropy6_source_nopr[64] =
    { 0xb3, 0xd0, 0x1b, 0xcb, 0x1e, 0xc7, 0x47,
     0xfd, 0xb7, 0xfe, 0xb5, 0xa7, 0xde,
     0x92, 0x80, 0x7a, 0xfa, 0x43, 0x38,
     0xab, 0xa1, 0xc8, 0x1c, 0xe1, 0xeb,
     0x50, 0x95, 0x5e, 0x12, 0x5a, 0xf4,
     0x6b, 0x19, 0xae, 0xd8, 0x91, 0x36,
     0x6e, 0xc0, 0xf7, 0x0b, 0x07, 0x90,
     0x37, 0xa5, 0xae, 0xb3, 0x3f, 0x07,
     0xf4, 0xc8, 0x94, 0xfd, 0xcd, 0xa3,
     0xff, 0x41, 0xe2, 0x86, 0x7a, 0xce,
     0x1a, 0xa0, 0x5c };

  const uint8_t nonce6_pers_nopr[16] =
    { 0x0a, 0xda, 0x12, 0x9f, 0x99, 0x48, 0x07,
     0x3d, 0x62, 0x8c, 0x11, 0x27, 0x4c,
     0xec, 0x3f, 0x69 };

  const uint8_t result6_nopr[16] =
    { 0xf3, 0x47, 0x10, 0xc9, 0xeb, 0xf9, 0xd5,
     0xaa, 0xa5, 0xf7, 0x97, 0xfd, 0x85,
     0xa1, 0xc4, 0x13 };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(6, entropy6_source_nopr, nonce6_pers_nopr, result6_nopr));

  // Count 7
  const uint8_t entropy7_source_nopr[64] =
    { 0x98, 0x48, 0x2e, 0x58, 0xe4, 0x4b, 0x8e,
     0x4a, 0x6b, 0x09, 0xfa, 0x02, 0xc0,
     0x5f, 0xcc, 0x49, 0x1d, 0xa0, 0x3a,
     0x47, 0x9a, 0x7f, 0xad, 0x13, 0xa8,
     0x3b, 0x60, 0x80, 0xd3, 0x0b, 0x3b,
     0x25, 0x5e, 0x01, 0xa4, 0x35, 0x68,
     0xa9, 0xd6, 0xdd, 0x5c, 0xec, 0xf9,
     0x9b, 0x0c, 0xe9, 0xfd, 0x59, 0x4d,
     0x69, 0xef, 0xf8, 0xfa, 0x88, 0x15,
     0x9b, 0x2d, 0xa2, 0x4c, 0x33, 0xba,
     0x81, 0xa1, 0x4d };

  const uint8_t nonce7_pers_nopr[16] =
    { 0x05, 0x2a, 0x5a, 0xd4, 0xcd, 0x38, 0xde,
     0x90, 0xe5, 0xd3, 0xc2, 0xfc, 0x43,
     0x0f, 0xa5, 0x1e };

  const uint8_t result7_nopr[16] =
    { 0x3f, 0x55, 0x14, 0x4e, 0xec, 0x26, 0x3a,
     0xed, 0x50, 0xf9, 0xc9, 0xa6, 0x41,
     0x53, 0x8e, 0x55 };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(7, entropy7_source_nopr, nonce7_pers_nopr, result7_nopr));

  // Count 8
  const uint8_t entropy8_source_nopr[64] =
    { 0x62, 0x38, 0xd4, 0x48, 0x01, 0x5e, 0x86,
     0xaa, 0x16, 0xaf, 0x62, 0xcd, 0xc2,
     0x87, 0xf1, 0xc1, 0x7b, 0x78, 0xa7,
     0x98, 0x09, 0xfa, 0x00, 0xb8, 0xc6,
     0x55, 0xe0, 0x67, 0x15, 0xcd, 0x2b,
     0x93, 0x5b, 0xf4, 0xdf, 0x96, 0x6e,
     0x3e, 0xc1, 0xf1, 0x4b, 0x28, 0xcc,
     0x1d, 0x08, 0x0f, 0x88, 0x2a, 0x72,
     0x15, 0xe2, 0x58, 0x43, 0x0c, 0x91,
     0xa4, 0xa0, 0xa2, 0xaa, 0x98, 0xd7,
     0xcd, 0x80, 0x53 };

  const uint8_t nonce8_pers_nopr[16] =
    { 0x00, 0x4c, 0xd2, 0xf2, 0x8f, 0x08, 0x3d,
     0x1c, 0xee, 0x68, 0x97, 0x5d, 0x5c,
     0xbb, 0xbe, 0x4f };

  const uint8_t result8_nopr[16] =
    { 0xb1, 0x37, 0x11, 0x9d, 0xbb, 0xd9, 0xd7,
     0x52, 0xa8, 0xdf, 0xce, 0xec, 0x05,
     0xb8, 0x84, 0xb6 };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(8, entropy8_source_nopr, nonce8_pers_nopr, result8_nopr));

  // Count 9
  const uint8_t entropy9_source_nopr[64] =
    { 0x50, 0xd3, 0xc4, 0xec, 0xb1, 0xd6, 0xe9,
     0x5a, 0xeb, 0xb8, 0x7e, 0x9e, 0x8a,
     0x5c, 0x86, 0x9c, 0x11, 0xfb, 0x94,
     0x5d, 0xfa, 0xd2, 0xe4, 0x5e, 0xe9,
     0x0f, 0xb6, 0x19, 0x31, 0xfc, 0xed,
     0xd4, 0x7d, 0x60, 0x05, 0xaa, 0x5d,
     0xf2, 0x4b, 0xb9, 0xef, 0xc1, 0x1b,
     0xbb, 0x96, 0xbb, 0x21, 0x06, 0x5d,
     0x44, 0xe2, 0x53, 0x2a, 0x1e, 0x17,
     0x49, 0x3f, 0x97, 0x4a, 0x4b, 0xf8,
     0xf8, 0xb5, 0x80 };

  const uint8_t nonce9_pers_nopr[16] =
    { 0xf9, 0x85, 0xb3, 0xea, 0x2d, 0x8b, 0x15,
     0xdb, 0x26, 0xa7, 0x18, 0x95, 0xa2,
     0xff, 0x57, 0xcd };

  const uint8_t result9_nopr[16] =
    { 0xeb, 0x41, 0x96, 0x28, 0xfb, 0xc4, 0x41,
     0xae, 0x6a, 0x03, 0xe2, 0x6a, 0xee,
     0xcb, 0x34, 0xa6 };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(9, entropy9_source_nopr, nonce9_pers_nopr, result9_nopr));

  // Count 10
  const uint8_t entropy10_source_nopr[64] =
    { 0xd2, 0x7c, 0xbe, 0xac, 0x39, 0xa6, 0xc8,
     0x99, 0x93, 0x81, 0x97, 0xf0, 0xe6,
     0x1d, 0xc9, 0x0b, 0xe3, 0xa3, 0xa2,
     0x0f, 0xa5, 0xc5, 0xe1, 0xf7, 0xa7,
     0x6a, 0xdd, 0xe0, 0x05, 0x98, 0xe5,
     0x95, 0x55, 0xc1, 0xe9, 0xfd, 0x10,
     0x2d, 0x4b, 0x52, 0xe1, 0xae, 0x9f,
     0xb0, 0x04, 0xbe, 0x89, 0x44, 0xba,
     0xd8, 0x5c, 0x58, 0xe3, 0x41, 0xd1,
     0xbe, 0xe0, 0x14, 0x05, 0x7d, 0xa9,
     0x8e, 0xb3, 0xbc };

  const uint8_t nonce10_pers_nopr[16] =
    { 0x10, 0x0f, 0x19, 0x69, 0x91, 0xb6, 0xe9,
     0x6f, 0x8b, 0x96, 0xa3, 0x45, 0x6f,
     0x6e, 0x2b, 0xaf };

  const uint8_t result10_nopr[16] =
    { 0xe3, 0xe0, 0x9d, 0x0e, 0xd8, 0x27, 0xe4,
     0xf2, 0x4a, 0x20, 0x55, 0x3f, 0xd1,
     0x08, 0x7c, 0x9d };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(10, entropy10_source_nopr, nonce10_pers_nopr, result10_nopr));

  // Count 11
  const uint8_t entropy11_source_nopr[64] =
    { 0x16, 0xf9, 0xf5, 0x35, 0x4d, 0x62, 0x4c,
     0x5a, 0xb1, 0xf8, 0x2c, 0x75, 0x0e,
     0x05, 0xf5, 0x1f, 0x2a, 0x2e, 0xec,
     0xa7, 0xe5, 0xb7, 0x74, 0xfd, 0x96,
     0x14, 0x8d, 0xdb, 0xa3, 0xb3, 0x8d,
     0x34, 0xba, 0x7f, 0x14, 0x72, 0x56,
     0x7c, 0x52, 0x08, 0x72, 0x52, 0x48,
     0x0d, 0x30, 0x5a, 0xd1, 0xc6, 0x9e,
     0x4a, 0xac, 0x84, 0x72, 0xa1, 0x54,
     0xae, 0x03, 0x51, 0x1d, 0x0e, 0x8a,
     0xac, 0x90, 0x5a };

  const uint8_t nonce11_pers_nopr[16] =
    { 0x88, 0xf5, 0x5d, 0x9b, 0xa8, 0xfe, 0xf7,
     0x82, 0x84, 0x83, 0x29, 0x83, 0x21,
     0x13, 0x3f, 0xec };

  const uint8_t result11_nopr[16] =
    { 0x07, 0xcd, 0x82, 0x10, 0x12, 0xef, 0x03,
     0xf1, 0x6d, 0x85, 0x10, 0xc2, 0x3b,
     0x86, 0xba, 0xf3 };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(11, entropy11_source_nopr, nonce11_pers_nopr, result11_nopr));

  // Count 12
  const uint8_t entropy12_source_nopr[64] =
    { 0x70, 0xaf, 0xbc, 0x83, 0xbf, 0x9f, 0xf0,
     0x95, 0x35, 0xd6, 0xf0, 0xdd, 0xc5,
     0x12, 0x78, 0xad, 0x79, 0x09, 0xf1,
     0x1e, 0x6f, 0x19, 0x8b, 0x59, 0x13,
     0x2c, 0x9e, 0x26, 0x9d, 0xeb, 0x41,
     0xba, 0x90, 0x1c, 0x62, 0x34, 0x62,
     0x83, 0xe2, 0x93, 0xb8, 0x71, 0x4f,
     0xd3, 0x24, 0x1a, 0xe8, 0x70, 0xf9,
     0x74, 0xff, 0x33, 0xc3, 0x5f, 0x9a,
     0xff, 0x05, 0x14, 0x4b, 0xe0, 0x39,
     0xd2, 0x4e, 0x50 };

  const uint8_t nonce12_pers_nopr[16] =
    { 0x12, 0x64, 0x79, 0xab, 0xd7, 0x0b, 0x25,
     0xac, 0xd8, 0x91, 0xe1, 0xc4, 0xc9,
     0x20, 0x44, 0xf9 };

  const uint8_t result12_nopr[16] =
    { 0x0f, 0x90, 0xdf, 0x35, 0x07, 0x41, 0xd8,
     0x85, 0x52, 0xa5, 0xb0, 0x3b, 0x64,
     0x88, 0xe9, 0xfb };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(12, entropy12_source_nopr, nonce12_pers_nopr, result12_nopr));

  // Count 13
  const uint8_t entropy13_source_nopr[64] =
    { 0x5e, 0x5a, 0x9e, 0x1e, 0x3c, 0xb8, 0x07,
     0x38, 0xc2, 0x38, 0x46, 0x4e, 0xde,
     0x1b, 0x6b, 0x6a, 0x32, 0x12, 0x61,
     0xa3, 0xb0, 0x06, 0xa9, 0x8a, 0x79,
     0x26, 0x5a, 0xd1, 0xf6, 0x35, 0x57,
     0x3b, 0xba, 0x48, 0xdc, 0xcf, 0x17,
     0xb1, 0x2f, 0x68, 0x68, 0x47, 0x82,
     0x52, 0xf5, 0x56, 0xb7, 0x7c, 0x3e,
     0xc5, 0x7a, 0x3b, 0xf6, 0xbb, 0x65,
     0x99, 0x42, 0x94, 0x53, 0xdb, 0x2d,
     0x05, 0x03, 0x52 };

  const uint8_t nonce13_pers_nopr[16] =
    { 0xa4, 0x5f, 0x2f, 0xca, 0x55, 0x30, 0x89,
     0xfe, 0x04, 0xe7, 0x83, 0x20, 0x59,
     0xdc, 0x79, 0x76 };

  const uint8_t result13_nopr[16] =
    { 0x6e, 0xb8, 0x5a, 0xe2, 0x40, 0x6c, 0x43,
     0x81, 0x4b, 0x68, 0x7f, 0x74, 0xf4,
     0xe9, 0x42, 0xbc };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(13, entropy13_source_nopr, nonce13_pers_nopr, result13_nopr));

  // Count 14
  const uint8_t entropy14_source_nopr[64] =
    { 0x31, 0xcf, 0xe6, 0x0e, 0x5e, 0xd1, 0x2f,
     0xf3, 0x7d, 0x7f, 0x22, 0x70, 0x96,
     0x3d, 0xef, 0x59, 0x87, 0x26, 0x32,
     0x0c, 0x02, 0xb9, 0x10, 0xb5, 0xc6,
     0xc7, 0x95, 0xe2, 0x20, 0x9b, 0x4b,
     0x4a, 0x95, 0x86, 0x6c, 0x64, 0xcb,
     0x09, 0x7a, 0xf1, 0xd6, 0x40, 0x4d,
     0x1e, 0x61, 0x82, 0xed, 0xf9, 0x60,
     0x0e, 0x18, 0x55, 0x34, 0x53, 0x75,
     0xb2, 0x01, 0x80, 0x1d, 0x6f, 0x4c,
     0x4e, 0x4b, 0x32 };

  const uint8_t nonce14_pers_nopr[16] =
    { 0x52, 0xdb, 0xb4, 0x32, 0x41, 0x00, 0x24,
     0x15, 0x96, 0x6e, 0xae, 0xc2, 0x61,
     0x5a, 0xba, 0x27 };

  const uint8_t result14_nopr[16] =
    { 0x2a, 0x27, 0x0f, 0x5e, 0xf8, 0x15, 0x66,
     0x5d, 0xdd, 0x07, 0x52, 0x7c, 0x48,
     0x71, 0x9a, 0xb1 };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(14, entropy14_source_nopr, nonce14_pers_nopr, result14_nopr));

  // Count 15
  const uint8_t entropyA_source_nopr[64] =
    { 0x5a, 0x19, 0x4d, 0x5e, 0x2b, 0x31, 0x58, 0x14,
      0x54, 0xde, 0xf6, 0x75, 0xfb, 0x79, 0x58, 0xfe,
      0xc7, 0xdb, 0x87, 0x3e, 0x56, 0x89, 0xfc, 0x9d,
      0x03, 0x21, 0x7c, 0x68, 0xd8, 0x03, 0x38, 0x20,
      0xf9, 0xe6, 0x5e, 0x04, 0xd8, 0x56, 0xf3, 0xa9,
      0xc4, 0x4a, 0x4c, 0xbd, 0xc1, 0xd0, 0x08, 0x46,
      0xf5, 0x98, 0x3d, 0x77, 0x1c, 0x1b, 0x13, 0x7e,
      0x4e, 0x0f, 0x9d, 0x8e, 0xf4, 0x09, 0xf9, 0x2e };

  const uint8_t nonceA_pers_nopr[16] =
    { 0x1b, 0x54, 0xb8, 0xff, 0x06, 0x42, 0xbf, 0xf5,
      0x21, 0xf1, 0x5c, 0x1c, 0x0b, 0x66, 0x5f, 0x3f };

  const uint8_t resultA_nopr[16] =
    { 0xa0, 0x54, 0x30, 0x3d, 0x8a, 0x7e, 0xa9, 0x88,
      0x9d, 0x90, 0x3e, 0x07, 0x7c, 0x6f, 0x21, 0x8f };

  ASSERT_TRUE(CTR_DRBG_NIST_Test(15, entropyA_source_nopr, nonceA_pers_nopr, resultA_nopr));
}

TEST(libopenabe, SymKeyOperations) {
  TEST_DESCRIPTION("Testing OpenABE keystore handling of symmetric keys is correct");
  shared_ptr<OpenABESymKey> symkey1(new OpenABESymKey);
  shared_ptr<OpenABESymKey> symkey2 = nullptr;
  OpenABERNG  *rng      = nullptr;
  OpenABEKeystore *ks	  = nullptr;

  ks  = new OpenABEKeystore;
  rng = new OpenABERNG;
  OpenABEByteString uid;
  rng->getRandomBytes(&uid, UID_LEN);
  // generate a random session key
  // symkey1 = new OpenABESymKey; // (OpenABE_SCHEME_AES_GCM, "sessionKey1");
  symkey1->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES);
  cout << "SymKey1: " << symkey1->toString() << endl;
  cout << "Length:  " << symkey1->getLength() << endl;

  ASSERT_TRUE(OpenABE_storeSymmetricKey(ks, "sessionKey1", symkey1) == OpenABE_NOERROR);

  OpenABEByteString sessionKeyExported;
  ASSERT_TRUE(OpenABE_exportKey(ks, "sessionKey1", &sessionKeyExported) == OpenABE_NOERROR);

  // cout << "Exported key: " << sessionKeyExported.toHex() << endl;
  ASSERT_TRUE(OpenABE_deleteSymmetricKey(ks, "sessionKey1") == OpenABE_NOERROR);

  // attempt to load recently exported key back into keystore
  ASSERT_TRUE(OpenABE_loadSymmetricKey(ks, "sessionKey1", &sessionKeyExported) == OpenABE_NOERROR);

  // now retrieve the symmetric key and print contents
  symkey2 = OpenABE_getSymmetricKey(ks, "sessionKey1");
  ASSERT_FALSE(symkey2 == nullptr);

  OpenABEByteString bytes;
  ASSERT_TRUE(ks->exportKeyToBytes("missingSessionKey", bytes) == OpenABE_ERROR_INVALID_INPUT);

  sessionKeyExported.insertFirstByte(0xAF); // add a bad header len (4 bytes)
  sessionKeyExported.insertFirstByte(0xBF);
  sessionKeyExported.insertFirstByte(0xCF);
  sessionKeyExported.insertFirstByte(0xDF);
  ASSERT_ANY_THROW(ks->parseKeyHeader("sessionKey2", bytes, sessionKeyExported));

  cout << "SymKey2: " << symkey2->toString() << endl;
  cout << "Length:  " << symkey2->getLength() << endl;
  ASSERT_TRUE(symkey1->getLength() == symkey2->getLength());
  ASSERT_TRUE(*symkey1 == *symkey2);

  SAFE_DELETE(rng);
  SAFE_DELETE(ks);
}

TEST(libopenabe, SymKeyAuthEnc) {
  TEST_DESCRIPTION("Testing that AES GCM implementation is correct");
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey);
  string plaintext1, plaintext2;
  OpenABEByteString sym_key_bytes, iv, ct, tag;

  /* generate a random secret key of a certain size */
  symkey->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES);
  cout << "SymmKey: " << symkey->toString() << endl;
  cout << "Length: " << symkey->getLength() << endl;

  symkey->exportKeyToBytes(sym_key_bytes);
  unique_ptr<OpenABESymKeyAuthEnc> authEnc(new OpenABESymKeyAuthEnc(DEFAULT_AES_SEC_LEVEL, sym_key_bytes));

  plaintext1 =  "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x39\x38\x37\x36\x35";
  /* optionally set additional authentication data */
  authEnc->setAddAuthData(NULL, 0);
  /* now we can encrypt */
  authEnc->encrypt(plaintext1, &iv, &ct, &tag);

  cout << "Ciphertext =>\n";
  // OpenABEByteString *iv		 = ct->getIV();
  // OpenABEByteString *ciphertext = ct->getCiphertext();
  // OpenABEByteString *tag 		 = ct->getTag();

  cout << "IV: " << iv.toHex() << endl;
  cout << "CT: " << ct.toHex() << endl;
  cout << "TG: " << tag.toHex() << endl;
  /* decrypt the ciphertext and check the authentication tag */
  ASSERT_TRUE(authEnc->decrypt(plaintext2, &iv, &ct, &tag));
}

TEST(libopenabe, SymKeyAuthEnc_Stream) {
  TEST_DESCRIPTION("Testing that SK streaming encryption is correct");
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey);
  OpenABEByteString plaintext, ciphertext, iv, tag;
  OpenABEByteString ptBlock1, ptBlock2, ctBlock1, ctBlock2;

  /* generate a random secret key of a certain size */
  symkey->generateSymmetricKey(DEFAULT_SYM_KEY_BYTES);
  cout << "SymmKey: " << symkey->toString() << endl;
  cout << "Length: " << symkey->getLength() << endl;

  unique_ptr<OpenABESymKeyAuthEncStream> authEncStream(new OpenABESymKeyAuthEncStream(DEFAULT_AES_SEC_LEVEL, symkey));

  ptBlock1 = "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x39\x38\x37\x36\x35";
  ptBlock2 = "\xA1\xB2\xC3\xD4\xE5\xF6\xA7\xB8\xC9\xD0\xE1\xF2\xA3\xB4\xC5\xD6";

  ASSERT_TRUE(authEncStream->encryptInit(&iv) == OpenABE_NOERROR);
  // set 0s for the AAD
  authEncStream->initAddAuthData(NULL, 0);
  ASSERT_TRUE(authEncStream->setAddAuthData() == OpenABE_NOERROR);

  // perform update 1
  ASSERT_TRUE(authEncStream->encryptUpdate(&ptBlock1, &ciphertext) == OpenABE_NOERROR);

  // perform update 2
  ASSERT_TRUE(authEncStream->encryptUpdate(&ptBlock2, &ciphertext) == OpenABE_NOERROR);

  ASSERT_TRUE(authEncStream->encryptFinalize(&ciphertext, &tag) == OpenABE_NOERROR);

  cout << "Final ciphertext: " << ciphertext.toHex() << endl;

  // split ciphertext into blocks
  ctBlock1 = ciphertext.getSubset(0, ptBlock1.size());
  ctBlock2 = ciphertext.getSubset(ptBlock1.size(), ptBlock2.size());
  cout << "ct1 : " << ctBlock1.toHex() << endl;
  cout << "ct2 : " << ctBlock2.toHex() << endl;

  // now try to decrypt the ciphertexts
  ASSERT_TRUE(authEncStream->decryptInit(&iv, &tag) == OpenABE_NOERROR);

  // set 0s for the AAD
  authEncStream->initAddAuthData(NULL, 0);
  ASSERT_TRUE(authEncStream->setAddAuthData() == OpenABE_NOERROR);

  // perform decrypt updates in order (note: order of blocks must be managed by the user)
  ASSERT_TRUE(authEncStream->decryptUpdate(&ctBlock1, &plaintext) == OpenABE_NOERROR);

  ASSERT_TRUE(authEncStream->decryptUpdate(&ctBlock2, &plaintext) == OpenABE_NOERROR);

  ASSERT_TRUE(authEncStream->decryptFinalize(&plaintext) == OpenABE_NOERROR);

  cout << "Original plaintext:  " << ptBlock1.toHex() << ptBlock2.toHex() << endl;
  cout << "Recovered plaintext: " << plaintext.toHex() << endl;
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

  OpenABE_ERROR err_code = authEncStream->decryptFinalize(&plaintext);
  ASSERT_FALSE(err_code == OpenABE_NOERROR);

  cout << "Recovered plaintext: " << plaintext.toHex() << endl;
}

TEST(libopenabe, SKSchemeStreamContext) {
  TEST_DESCRIPTION("Testing that streaming SK scheme context is correct");
  OpenABEByteString plaintext, ciphertext, iv, tag;
  OpenABEByteString ptBlock1, ptBlock2, ctBlock1, ctBlock2;

  unique_ptr<OpenABEContextSchemeStreamSKE> schemeStreamSKE(new OpenABEContextSchemeStreamSKE);

  ASSERT_TRUE(schemeStreamSKE->keygen("key1") == OpenABE_NOERROR);

  ASSERT_TRUE(schemeStreamSKE->keygen("key2") == OpenABE_NOERROR);

  ptBlock1 = "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x39\x38\x37\x36\x35";
  ptBlock2 = "\xA1\xB2\xC3\xD4\xE5\xF6\xA7\xB8\xC9\xD0\xE1\xF2\xA3\xB4\xC5\xD6";

  ASSERT_TRUE(schemeStreamSKE->encryptInit("key1", &iv) == OpenABE_NOERROR);

  // perform update 1
  ASSERT_TRUE(schemeStreamSKE->encryptUpdate(&ptBlock1, &ciphertext) == OpenABE_NOERROR);
  // perform update 2
  ASSERT_TRUE(schemeStreamSKE->encryptUpdate(&ptBlock2, &ciphertext) == OpenABE_NOERROR);
  ASSERT_TRUE(schemeStreamSKE->encryptFinalize(&ciphertext, &tag) == OpenABE_NOERROR);

  cout << "Final ciphertext: " << ciphertext.toHex() << endl;

  // split ciphertext into blocks
  ctBlock1 = ciphertext.getSubset(0, ptBlock1.size());
  ctBlock2 = ciphertext.getSubset(ptBlock1.size(), ptBlock2.size());
  cout << "ct1 : " << ctBlock1.toHex() << endl;
  cout << "ct2 : " << ctBlock2.toHex() << endl;

  // now try to decrypt the ciphertexts
  ASSERT_TRUE(schemeStreamSKE->decryptInit("key1", &iv, &tag) == OpenABE_NOERROR);

  // perform decrypt updates in order (note: order of blocks must be managed by the user)
  ASSERT_TRUE(schemeStreamSKE->decryptUpdate(&ctBlock1, &plaintext) == OpenABE_NOERROR);

  ASSERT_TRUE(schemeStreamSKE->decryptUpdate(&ctBlock2, &plaintext) == OpenABE_NOERROR);

  ASSERT_TRUE(schemeStreamSKE->decryptFinalize(&plaintext) == OpenABE_NOERROR);

  cout << "Original plaintext:  " << ptBlock1.toHex() << ptBlock2.toHex() << endl;
  cout << "Recovered plaintext: " << plaintext.toHex() << endl;
  ASSERT_TRUE(plaintext == (ptBlock1 + ptBlock2));

//	plaintext.clear();
//	ASSERT_TRUE(schemeStreamSKE->decryptInit("key2", &iv, &tag) == OpenABE_NOERROR);
//
////	// set 0s for the AAD
////	schemeStreamSKE->initAddAuthData(NULL, 0);
////	ASSERT_TRUE(schemeStreamSKE->setAddAuthData() == OpenABE_NOERROR);
//
//	// perform decrypt updates in order (note: order of blocks must be managed by the user)
//	ASSERT_TRUE(schemeStreamSKE->decryptUpdate(&ctBlock2, &plaintext) == OpenABE_NOERROR);
//
//	ASSERT_TRUE(schemeStreamSKE->decryptUpdate(&ctBlock1, &plaintext) == OpenABE_NOERROR);
//
//	OpenABE_ERROR err_code = schemeStreamSKE->decryptFinalize(&plaintext);
//	ASSERT_TRUE(err_code == OpenABE_NOERROR);
//
//	cout << "Recovered plaintext: " << plaintext.toHex() << endl;
}

TEST(libopenabe, SymKeyHandleContext) {
  TEST_DESCRIPTION("Testing that Symmetric Key handle works correctly");
  OpenABEByteString key;
  string raw_key, key_data, ciphertext, plaintext1, plaintext2;

  cout << "Generate sym key..." << endl;
  generateSymmetricKey(raw_key, DEFAULT_SYM_KEY_BYTES);
  key += raw_key;
  cout << "key: " << key.toLowerHex() << endl;

  cout << "Create SymKey handle" << endl;
  std::unique_ptr<OpenABESymKeyHandle> keyHandle(new OpenABESymKeyHandleImpl(raw_key));

  // test key exporting
  keyHandle->exportKey(key_data);
  cout << "key_data size: " << key_data.size() << endl;
  // test encryption
  plaintext1 = "this is plaintext!";
  keyHandle->encrypt(ciphertext, plaintext1);

  // test decryption
  keyHandle->decrypt(plaintext2, ciphertext);

  ASSERT_TRUE(plaintext1.compare(plaintext2) == 0);

  // keyHandle->cleanup();
  cout << "Successful Decryption!" << endl;
}

TEST(libopenabe, PKOPDHKemContext) {
  TEST_DESCRIPTION("Testing that PK One-pass DH KEM is correct");
  OpenABEContextPKE *kemContext = NULL;
  unique_ptr<OpenABERNG> rng(new OpenABERNG);
  shared_ptr<OpenABEKey> senderPK = nullptr;
  shared_ptr<OpenABESymKey> symkey(new OpenABESymKey), newkey(new OpenABESymKey);
  OpenABECiphertext *ciphertext = NULL;
  OpenABEByteString senderID;

  // create new KEM context for PKE ECC MQV scheme
  kemContext = OpenABE_createContextPKE(&rng, OpenABE_SCHEME_PK_OPDH);

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(kemContext->generateParams("NIST_P256") == OpenABE_NOERROR);

  // Compute party A's static public and private key
  ASSERT_TRUE(kemContext->generateDecryptionKey("ID_A", "public_A", "private_A") == OpenABE_NOERROR);

  // Compute party B's static public and private key
  ASSERT_TRUE(kemContext->generateDecryptionKey("ID_B", "public_B", "private_B") == OpenABE_NOERROR);

  // get PK of sender (assumes it has already been loaded)
  senderPK = kemContext->getKeystore()->getPublicKey("public_A");
  senderID = senderPK->getUID();

  // Encrypt a test key using the KEM mode
  // symkey = new OpenABESymKey;
  ciphertext = new OpenABECiphertext;
  ASSERT_TRUE(kemContext->encryptKEM(NULL, "public_B", &senderID, DEFAULT_SYM_KEY_BITS, symkey, ciphertext) == OpenABE_NOERROR);

  string symKeyStr = symkey->toString();
  cout << "Orig symmetric key: " << symKeyStr << endl;

  // newkey = new OpenABESymKey;
  ASSERT_TRUE(kemContext->decryptKEM("public_A", "private_B", ciphertext, DEFAULT_SYM_KEY_BITS, newkey) == OpenABE_NOERROR);

  string newKeyStr = newkey->toString();
  cout << "Recvd symmetric key: " << newKeyStr << endl;
  ASSERT_TRUE(symKeyStr.compare(newKeyStr) == 0);

  SAFE_DELETE(ciphertext);
  SAFE_DELETE(kemContext);
}

TEST(libopenabe, PKSchemeContext) {
  TEST_DESCRIPTION("Testing that PK scheme context works correctly");
  OpenABERNG rng;
  OpenABECiphertext ciphertext;

  // create new KEM context for PKE ECC MQV scheme
  unique_ptr<OpenABEContextSchemePKE> schemeContext = OpenABE_createContextPKESchemeCCA(OpenABE_SCHEME_PK_OPDH);

  // Generate a set of parameters for an ABE authority
  ASSERT_TRUE(schemeContext->generateParams("NIST_P256") == OpenABE_NOERROR);

  // Compute party A's static public and private key
  ASSERT_TRUE(schemeContext->keygen("ID_A", "public_A", "private_A") == OpenABE_NOERROR);

  // Compute party B's static public and private key
  ASSERT_TRUE(schemeContext->keygen("ID_B", "public_B", "private_B") == OpenABE_NOERROR);

  // Test load / delete (perhaps, we should provide convenience functions for this)
  OpenABEByteString publicKeyA, publicKeyA_bad, privateKeyB;

  ASSERT_TRUE(schemeContext->exportKey("public_A", publicKeyA) == OpenABE_NOERROR);
  ASSERT_TRUE(schemeContext->exportKey("private_B", privateKeyB) == OpenABE_NOERROR);

  publicKeyA_bad = publicKeyA;
  // swap two positions in header
  publicKeyA_bad[5] = publicKeyA_bad[6]; // tweak header a little bit
  publicKeyA_bad[6] = publicKeyA[5];

  // delete them
  ASSERT_TRUE(schemeContext->deleteKey("public_A") == OpenABE_NOERROR);
  ASSERT_TRUE(schemeContext->deleteKey("private_B") == OpenABE_NOERROR);

  // attempt to load a key that was just deleted
  ASSERT_TRUE(schemeContext->loadPublicKey("public_A", publicKeyA_bad) != OpenABE_NOERROR);

  // attempt to load a key that was just deleted
  ASSERT_TRUE(schemeContext->loadPublicKey("public_A", publicKeyA) == OpenABE_NOERROR);

  // attempt to load a key that was just deleted
  ASSERT_TRUE(schemeContext->loadPrivateKey("private_B", privateKeyB) == OpenABE_NOERROR);

  OpenABEByteString plaintext1, plaintext2;
  // plaintext1 = "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45\x46";
  rng.getRandomBytes(&plaintext1, 128);
  const string pt1 = plaintext1.toString();
  ASSERT_TRUE(schemeContext->encrypt(NULL, "public_B", "public_A", pt1, &ciphertext) == OpenABE_NOERROR);

  cout << "Orig m: " << plaintext1.toHex() << endl;

  string pt2;
  ASSERT_TRUE(schemeContext->decrypt("public_A", "private_B", pt2, &ciphertext) == OpenABE_NOERROR);

  plaintext2 = pt2;
  cout << "Recv m: " << plaintext2.toHex() << endl;

  ASSERT_TRUE(plaintext1 == plaintext2);
}

TEST(libopenabe, PKSIGLowLevelContext) {
  TEST_DESCRIPTION("Testing that PKSIG low level context is correct");
  OpenABEByteString message, signature;

  unique_ptr<OpenABEContextPKSIG> pksig(new OpenABEContextPKSIG);

  ASSERT_TRUE(pksig->generateParams("NIST_P256") == OpenABE_NOERROR);

  ASSERT_TRUE(pksig->keygen("public_key", "private_key") == OpenABE_NOERROR);

  // get the secret key
  shared_ptr<OpenABEPKey> sk = static_pointer_cast<OpenABEPKey>(pksig->getKeystore()->getSecretKey("private_key"));
  ASSERT_TRUE(sk != nullptr);

  // get the public key
  shared_ptr<OpenABEPKey> pk = static_pointer_cast<OpenABEPKey>(pksig->getKeystore()->getPublicKey("public_key"));
  ASSERT_TRUE(pk != nullptr);

  message = "hello world";
  ASSERT_TRUE(pksig->sign(sk.get(), &message, &signature) == OpenABE_NOERROR);

  cout << "Signature: " << signature.toLowerHex() << endl;
  cout << "Sig Len:   " << signature.size() << endl;

  ASSERT_TRUE(pksig->verify(pk.get(), &message, &signature) == OpenABE_NOERROR);
}


TEST(libopenabe, PKSIGSchemeContext) {
  TEST_DESCRIPTION("Testing that PKSIG scheme context (wrapper around PKSIG low-level) works correctly");
  unique_ptr<OpenABEContextSchemePKSIG> schemeContext = nullptr;
  OpenABEByteString message, signature;
  OpenABEByteString outputPK, outputSK;

  schemeContext = OpenABE_createContextPKSIGScheme();

  ASSERT_TRUE(schemeContext->generateParams("NIST_P256") == OpenABE_NOERROR);

  ASSERT_TRUE(schemeContext->keygen("public_key", "private_key") == OpenABE_NOERROR);

  ASSERT_TRUE(schemeContext->exportKey("public_key", outputPK) == OpenABE_NOERROR);

  ASSERT_TRUE(schemeContext->exportKey("private_key", outputSK) == OpenABE_NOERROR);

  cout << "outputPK:\n" << outputPK.toString() << endl;
  cout << "outputSK:\n" << outputSK.toString() << endl;

  ASSERT_TRUE(schemeContext->deleteKey("public_key") == OpenABE_NOERROR);
  ASSERT_TRUE(schemeContext->deleteKey("private_key") == OpenABE_NOERROR);

  // attempt to load a key that was just deleted
  ASSERT_TRUE(schemeContext->loadPublicKey("public_key", outputPK) == OpenABE_NOERROR);

  // attempt to load a key that was just deleted
  ASSERT_TRUE(schemeContext->loadPrivateKey("private_key", outputSK) == OpenABE_NOERROR);

  message = "hello world";
  // sign a message using the private key
  ASSERT_TRUE(schemeContext->sign("private_key", &message, &signature) == OpenABE_NOERROR);

  cout << "Signature: " << signature.toLowerHex() << endl;
  cout << "Sig Len:   " << signature.size() << endl;

  ASSERT_TRUE(schemeContext->verify("public_key", &message, &signature) == OpenABE_NOERROR);
}

TEST(libopenabe, PasswordHashingTests) {
  TEST_DESCRIPTION("Testing that password hashing utility is correct");
  string hash, hash1;
  string password1, password2;

  password1 = "password";
  password2 = "passw0rd";
  generateHash(hash, password1);

  cout << "Returned hash: " << hash << endl;

  // verify hash/password1 combo (should pass)
  ASSERT_TRUE(checkPassword(hash, password1));

  // verify hash/password2 combo (should fail)
  ASSERT_FALSE(checkPassword(hash, password2));

  string fake_hash = "abcdefoobar123456789123xyz";
  ASSERT_THROW(checkPassword(fake_hash, password1), OpenABE_ERROR);
}

TEST(libopenabe, PasswodHashingWithInvalidInputs) {
  TEST_DESCRIPTION("Testing that password hashing utility handles very long inputs");
  string hash1, hash2, password1 = "", password2 = "";
  size_t bits_20 = (1 << 20);
  size_t bits_24 = (1 << 24);
  for(size_t i = 0; i < bits_20; i++) {
    password1 += "a";
  }

  for(size_t i = 0; i < bits_24; i++) {
    password2 += "a";
  }

  generateHash(hash1, password1);
  generateHash(hash2, password2);
  ASSERT_TRUE(hash1.compare(hash2) != 0);
}

TEST(libopenabe, PasswordHashingWithNoInput) {
  TEST_DESCRIPTION("Testing that password hashing utility handles invalid inputs with an exception");
  string hash;
  ASSERT_ANY_THROW(generateHash(hash, ""));
}

TEST(libopenabe, CryptoBoxCPABEContext) {
  TEST_DESCRIPTION("Testing that crypto box for CP-ABE context works");
  string mpk, msk;
  string ct1, ct2;

  OpenABECryptoContext cpabe("CP-ABE");

  cpabe.generateParams();
  cpabe.exportPublicParams(mpk);
  cpabe.exportSecretParams(msk);

  cpabe.keygen("|one|two|three", "key1");
  cpabe.keygen("|one|two", "key2");

  string pt1 = "hello world!", pt2;
  cpabe.encrypt("((one or two) and three)", pt1, ct1);

  cout << "Ciphertext: " << ct1.size() << endl;

  ASSERT_TRUE(cpabe.decrypt("key1", ct1, pt2));

  string pt3;
  ASSERT_FALSE(cpabe.decrypt("key2", ct1, pt3));

  OpenABECryptoContext cpabe2("CP-ABE");

  cpabe2.importPublicParams(mpk);
  cpabe2.importSecretParams(msk);

  cpabe2.keygen("|four|five|six", "key1");
  cpabe2.keygen("|five", "key2");

  pt1 = "this is another plaintext!";
  pt2.clear();
  pt3.clear();
  cpabe2.encrypt("(four and five)", pt1, ct2);
  ASSERT_ANY_THROW(cpabe2.encrypt("(four or ", pt2, ct1));

  ASSERT_TRUE(cpabe2.decrypt("key1", ct2, pt2));
  ASSERT_FALSE(cpabe2.decrypt("key2", ct2, pt3));
}

TEST(libopenabe, CryptoBoxCPABEContextMinusBase64Encoding) {
  TEST_DESCRIPTION("Testing that crypto box for CP-ABE context works (without base64 encoding)");
  string mpk, msk;
  string ct1, ct2;

  OpenABECryptoContext cpabe("CP-ABE", false);

  cpabe.generateParams();
  cpabe.exportPublicParams(mpk);
  cpabe.exportSecretParams(msk);

  cpabe.keygen("|one|two|three", "key1");
  cpabe.keygen("|one|two", "key2");

  string pt1 = "hello world!", pt2;
  cpabe.encrypt("((one or two) and three)", pt1, ct1);

  cout << "Ciphertext: " << ct1.size() << endl;

  ASSERT_TRUE(cpabe.decrypt("key1", ct1, pt2));

  string pt3;
  ASSERT_FALSE(cpabe.decrypt("key2", ct1, pt3));

  OpenABECryptoContext cpabe2("CP-ABE", false);

  cpabe2.importPublicParams(mpk);
  cpabe2.importSecretParams(msk);

  cpabe2.keygen("|four|five|six", "key1");
  cpabe2.keygen("|five", "key2");

  pt1 = "this is another plaintext!";
  pt2.clear();
  pt3.clear();
  cpabe2.encrypt("(four and five)", pt1, ct2);
  ASSERT_ANY_THROW(cpabe2.encrypt("(four or ", pt2, ct1));

  ASSERT_TRUE(cpabe2.decrypt("key1", ct2, pt2));
  ASSERT_FALSE(cpabe2.decrypt("key2", ct2, pt3));
}

TEST(libopenabe, CryptoBoxCPABEContextBad0) {
  TEST_DESCRIPTION("Testing that crypto box for CP-ABE context with invalid ciphertext -- failure case");

  OpenABECryptoContext cpabe("CP-ABE", false);

  cpabe.generateParams();
}

TEST(libopenabe, CryptoBoxCPABEContextBad1) {
  TEST_DESCRIPTION("Testing that crypto box for CP-ABE context with invalid scheme identifier -- failure case");

  unique_ptr<OpenABECryptoContext> cpabe = nullptr;

  ASSERT_ANY_THROW(cpabe.reset(new OpenABECryptoContext("CP-ABES")));
}

TEST(libopenabe, CryptoBoxCPABEContextBad2) {
  TEST_DESCRIPTION("Testing that crypto box for CP-ABE context with bad inputs -- failure case");

  OpenABECryptoContext cpabe("CP-ABE");

  cpabe.generateParams();

  ASSERT_ANY_THROW(cpabe.keygen("one and three", "key0"));
}

TEST(libopenabe, CryptoBoxCPABEContextBad3) {
  TEST_DESCRIPTION("Testing that crypto box for CP-ABE context with bad inputs -- failure case");

  OpenABECryptoContext cpabe("CP-ABE");

  cpabe.generateParams();

  cpabe.keygen("one|three", "key0");

  string pt1, ct1;
  ASSERT_ANY_THROW(cpabe.encrypt("four|five", pt1, ct1));
}

TEST(libopenabe, CryptoBoxKPABEContext) {
  TEST_DESCRIPTION("Testing that crypto box for KP-ABE context works");
  string pt1, pt2, pt3, ct1, ct2;

  OpenABECryptoContext kpabe("KP-ABE");

  kpabe.generateParams();

  kpabe.keygen("((one or two) and three)", "key1");

  pt1 = "hello world!";
  kpabe.encrypt("two|three", pt1, ct1);
  // enc input "Date:" is specified incorrectly so should throw an exception
  ASSERT_ANY_THROW(kpabe.encrypt("two|Date:January 1, 1971", pt1, ct2));

  ASSERT_TRUE(kpabe.decrypt("key1", ct1, pt2));
  ASSERT_FALSE(kpabe.decrypt("key2", ct1, pt3));
}

TEST(libopenabe, CryptoBoxKPABEContextMinusBase64Encoding) {
  TEST_DESCRIPTION("Testing that crypto box for KP-ABE context works (without base64 encoding)");
  string pt1, pt2, pt3, ct1, ct2;

  OpenABECryptoContext kpabe("KP-ABE", false);

  kpabe.generateParams();

  kpabe.keygen("((one or two) and three)", "key1");

  pt1 = "hello world!";
  kpabe.encrypt("two|three", pt1, ct1);
  // enc input "Date:" is specified incorrectly so should throw an exception
  ASSERT_ANY_THROW(kpabe.encrypt("two|Date:January 1, 1971", pt1, ct2));

  ASSERT_TRUE(kpabe.decrypt("key1", ct1, pt2));
  ASSERT_FALSE(kpabe.decrypt("key2", ct1, pt3));
}

TEST(libopenabe, CryptoBoxPKEContext) {
  TEST_DESCRIPTION("Testing that crypto box for PKE context works");
  string pk, sk;
  string pt1, pt2, ct, ct1;
  string user1PK, user1SK, user2PK, user2SK;

  OpenPKEContext pke, pke2;

  pke.keygen("user1");
  pke.exportPublicKey("user1", user1PK);
  pke.exportPrivateKey("user1", user1SK);

  pke.keygen("user2");
  pke.exportPublicKey("user2", user2PK);
  pke.exportPrivateKey("user2", user2SK);

  pt1 = "hello world!";
  pke.encrypt("user2", pt1, ct);

  ASSERT_TRUE(pke.decrypt("user2", ct, pt2));

  pt2.clear();
  ASSERT_FALSE(pke.decrypt("user1", ct, pt2));

  pke2.importPrivateKey("user2", user2SK);

  pt2.clear();
  ASSERT_TRUE(pke.decrypt("user2", ct, pt2));
}

TEST(libopenabe, CryptoBoxPKEContextMinusBase64Encoding) {
  TEST_DESCRIPTION("Testing that crypto box for PKE context works (without base64 encoding)");
  string pk, sk;
  string pt1, pt2, ct, ct1;
  string user1PK, user1SK, user2PK, user2SK;

  OpenPKEContext pke("NIST_P256", false), pke2("NIST_P256", false);

  pke.keygen("user1");
  pke.exportPublicKey("user1", user1PK);
  pke.exportPrivateKey("user1", user1SK);

  pke.keygen("user2");
  pke.exportPublicKey("user2", user2PK);
  pke.exportPrivateKey("user2", user2SK);

  pt1 = "hello world!";
  pke.encrypt("user2", pt1, ct);

  ASSERT_TRUE(pke.decrypt("user2", ct, pt2));

  pt2.clear();
  ASSERT_FALSE(pke.decrypt("user1", ct, pt2));

  pke2.importPrivateKey("user2", user2SK);

  pt2.clear();
  ASSERT_TRUE(pke.decrypt("user2", ct, pt2));
}

TEST(libopenabe, CryptoBoxPKSIGContext) {
  TEST_DESCRIPTION("Testing that crypto box for PKSIG context works");
  string pk, sk, msg1, msg2, sig;

  OpenPKSIGContext pksig;
  pksig.keygen("user1");
  pksig.exportPublicKey("user1", pk);
  pksig.exportPrivateKey("user1", sk);

  msg1 = "hello world!";
  pksig.sign("user1", msg1, sig);

  ASSERT_TRUE(pksig.verify("user1", msg1, sig));

  msg2 = "an invalid message!";
  ASSERT_FALSE(pksig.verify("user1", msg2, sig));
}

TEST(libopenabe, CryptoBoxPKSIGContextMinusBase64Encoding) {
  TEST_DESCRIPTION("Testing that crypto box for PKSIG context works (without base64 encoding)");
  string pk, sk, msg1, msg2, sig;

  OpenPKSIGContext pksig("NIST_P256", false);
  pksig.keygen("user1");
  pksig.exportPublicKey("user1", pk);
  pksig.exportPrivateKey("user1", sk);

  msg1 = "hello world!";
  pksig.sign("user1", msg1, sig);

  ASSERT_TRUE(pksig.verify("user1", msg1, sig));

  msg2 = "an invalid message!";
  ASSERT_FALSE(pksig.verify("user1", msg2, sig));
}

struct thread_data {
  int id, time;
  OpenABERNG *shared_rng;
};

void *oabe_thread(void *args) {
  OpenABEStateContext oabe;
  OpenABERNG local_rng;
  OpenABEByteString buf1, buf2;
  struct thread_data *data = (struct thread_data *) args;
  data->shared_rng->getRandomBytes(&buf1, 16); // 128-bit key
  local_rng.getRandomBytes(&buf2, 16);
  usleep(data->time);
  cout << "client " << data->id << ": " << buf1.toHex() << "," << buf2.toHex() << endl;
  //cout << "ctx_t ptr => " << core_get() << endl;
  return NULL;
}

TEST(libopenabe, OpenABEThreadContext) {
  TEST_DESCRIPTION("Testing that OpenABE can be used with multi-threaded applications");
  int count = 4;
  pthread_t threads[count];
  struct thread_data data[count];
  OpenABERNG rng;
  for(int i = 0; i < count; i++) {
    data[i].time = (i + 1) * 1000;
    data[i].id   = i + 1;
    data[i].shared_rng  = &rng;
    if(pthread_create(&threads[i], NULL, oabe_thread, (void *) &data[i])) {
        cerr << "Failed to create thread!" << endl;
        return;
    }
  }

  for(int i = 0; i < count; i++) {
    if(pthread_join(threads[i], NULL)) {
        cerr << "Failed to join thread." << endl;
        return;
    }
  }
  return;
}

}

int main(int argc, char **argv)
{
  cout << "libopenabe v" << (OpenABE_LIBRARY_VERSION / 100.) << " test utility." << endl << endl;

  InitializeOpenABE();

  ::testing::InitGoogleTest(&argc, argv);
  int rc = RUN_ALL_TESTS();

  ShutdownOpenABE();

  return rc;
}

