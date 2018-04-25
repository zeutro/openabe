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
/// \file   test_abe.cpp
///
/// \brief  Unit testing utility for OpenABE schemes.
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

#define COMMA   ','
#define TEST_DESCRIPTION(desc) RecordProperty("description", desc)
#define TESTSUITE_DESCRIPTION(desc) ::testing::Test::RecordProperty("description", desc)

string createAttribute(int i)
{
    stringstream ss;
    ss << "Attr" << i;
    return ss.str();
}

bool getOpenABEAttributeList(int max, vector<string> & attrList)
{
    if(max <= 0) { return false; }
    int start = 0;
    // reset
    attrList.clear();
    for(int i = start; i <= max; i++) {
        attrList.push_back(createAttribute(i));
    }
    return true;
}

// returns an evenly distributed / balanced policy tree
string getBalancedOpenABETree(int start, int end) {
    if(start == end) { return createAttribute(start); }
    int mid = ceil((start + (end - start) / 2.0));
    if(mid == 0) {
        return "(" + createAttribute(start) + " and " + createAttribute(end) + ")";
    }
    else {
        return "(" + getBalancedOpenABETree(start, mid-1) + " and " + getBalancedOpenABETree(mid, end) + ")";
    }
}

// returns a right-sided skewed policy tree
string getOpenABEPolicyString(int max)
{
    string policystr;
    if(max >= 2) {
        policystr = "(" + createAttribute(0) + " and " + createAttribute(1) + ")";
    }
    else if(max == 1) {
        policystr = createAttribute(0);
    }

    for(int i = 2; i <= max; i++)
    {
        policystr = "(" + policystr + " and " + createAttribute(i) + ")";
    }

    return policystr;
}

bool runLSSSTest(string policy_str, string attr_list_str, bool verbose = false)
{
    // Create a pairing object
    OpenABEPairing pairing(DEFAULT_BP_PARAM);
    // instantiate RNG
    OpenABERNG rng;

    unique_ptr<OpenABEPolicy> policy = createPolicyTree(policy_str);
    if(verbose) {
        cout << "Policy: " << policy->toString() << endl;
    }
    ZP secret = pairing.randomZP(&rng);
    // Compute the secret shares
    OpenABELSSS lsss(&pairing, &rng);
    lsss.shareSecret(policy.get(), secret);
    // Get the resulting shares
    OpenABELSSSRowMap shares = lsss.getRows();
    cout << "Obtained " << shares.size() << " secret shares" << endl;

    OpenABELSSS recoveryLsss(&pairing, &rng);

    // OpenABEAttributeList *attrList = new OpenABEAttributeList(S.size(), S);
    unique_ptr<OpenABEAttributeList> attrList = createAttributeList(attr_list_str);
    if(verbose) {
    	cout << "AttrList: " << attrList->toString() << endl;
    }
    if(recoveryLsss.recoverCoefficients(policy.get(), attrList.get()) == false)
        return false;
    OpenABELSSSRowMap coefficients = recoveryLsss.getRows();
    cout << "Recovered " << coefficients.size() << " coefficients." << endl;

    ZP recSecret = recoveryLsss.LSSStestSecretRecovery(coefficients,  shares);
    return secret == recSecret;
}

TEST(Attribute, SerializeAndDeserialize) {
    TEST_DESCRIPTION("Testing serialize and deserialize for attribute lists");
    OpenABEAttributeList attr_list;
    attr_list.addAttribute("Alice");
    attr_list.addAttribute("Bob");

    OpenABEByteString bytes;
    attr_list.serialize(bytes);
    OpenABEAttributeList attr_list2;
    attr_list2.deserialize(bytes);

    ASSERT_TRUE(attr_list.isEqual(&attr_list2));
}

class PolicyParser : public ::testing::Test {
 protected:
  virtual void SetUp() { }

};

TEST_F(PolicyParser, OrderOfParanthesis) {
    TEST_DESCRIPTION("Testing that basic ordering of parenthesis does not matter");
    unique_ptr<OpenABEPolicy> s1 = createPolicyTree("(one or two) and three");
    unique_ptr<OpenABEPolicy> s2 = createPolicyTree("three and (one or two)");
    ASSERT_TRUE(s1 != nullptr);
    ASSERT_TRUE(s2 != nullptr);
    set<string> attr_set1 = s1->getAttrCompleteSet();
    set<string> attr_set2 = s2->getAttrCompleteSet();
    ASSERT_EQ(attr_set1, attr_set2);
}

TEST_F(PolicyParser, DateRangePolicy) {
    TEST_DESCRIPTION("Testing that we can handle range of dates policies");
    ASSERT_TRUE(createPolicyTree("Date = January 1-31, 2016") != nullptr);
    ASSERT_TRUE(createPolicyTree("Date = February 1-15, 2016") != nullptr);
    ASSERT_TRUE(createPolicyTree("Date = March 21-28, 2016") != nullptr);
}

TEST_F(PolicyParser, ValidDatePolicy) {
    TEST_DESCRIPTION("Testing that we can handle date type policies");
    ASSERT_TRUE(createPolicyTree("Date = January 5, 2016") != nullptr);
    ASSERT_TRUE(createPolicyTree("Date > January 5, 2016") != nullptr);
    ASSERT_TRUE(createPolicyTree("Date < January 5, 2016") != nullptr);
    ASSERT_TRUE(createPolicyTree("Date <= January 5, 2016") != nullptr);
    ASSERT_TRUE(createPolicyTree("Date >= January 5, 2016") != nullptr);
}

TEST_F(PolicyParser, InvalidDate) {
    TEST_DESCRIPTION("Testing that an exception is thrown for invalid dates before unix epoch");
    ASSERT_TRUE(createPolicyTree("Date = January 1, 1968") == nullptr);
}

TEST_F(PolicyParser, InvalidStartDateRange) {
    TEST_DESCRIPTION("Testing that an exception is thrown for an invalid date range");
    ASSERT_TRUE(createPolicyTree("Date = January 0-10, 1970") == nullptr);
}


TEST_F(PolicyParser, InvalidEndDateRange) {
    TEST_DESCRIPTION("Testing that an exception is thrown for an invalid date range");
    ASSERT_TRUE(createPolicyTree("Date = January 1-40, 1970") == nullptr);
}

TEST_F(PolicyParser, InvalidDateFormat) {
    TEST_DESCRIPTION("Testing that dates are specified correctly");
    ASSERT_TRUE(createPolicyTree("(One or Two) and (Date : January 1, 1970)") == nullptr);
}

TEST_F(PolicyParser, IntegerRangePolicy) {
    TEST_DESCRIPTION("Testing that range of integers supported in the policy");
    ASSERT_TRUE(createPolicyTree("Level in (2-35)") != nullptr);
    unique_ptr<OpenABEPolicy> s1 = createPolicyTree("Level > 2 and Level < 35");
    ASSERT_TRUE(s1 != nullptr);
}

TEST_F(PolicyParser, InvalidExpInts) {
    // verifying invalid policies are caught appropriately
    TEST_DESCRIPTION("Testing that integers in expint can be represented by number of bits specified");
    // make sure integers in expint can be represented by number of bits specified
    ASSERT_TRUE(createPolicyTree("Month < 16#4") == nullptr);
}

TEST_F(PolicyParser, InvalidExpIntsWithZero) {
    TEST_DESCRIPTION("Testing that integers in expint can be represented by number of bits specified");
    // make sure integers in expint can be represented by number of bits specified
    ASSERT_TRUE(createPolicyTree("Month < 4#0") == nullptr);
}

TEST_F(PolicyParser, NegativeIntegerInPolicies) {
    TEST_DESCRIPTION("Testing that negative integers are not allowed");
    // make sure negative integers are not allowed
    ASSERT_TRUE(createPolicyTree("Month > -1#4") == nullptr);
    ASSERT_TRUE(createPolicyTree("Month < -3#4") == nullptr);
}

TEST_F(PolicyParser, LessThanGreaterThanNotInAttributeList) {
    TEST_DESCRIPTION("Testing that >,<=,etc cannot be added in attribute lists");
    // make sure we can't add >,<=,etc in attribute lists
    ASSERT_TRUE(createAttributeList("Alice|Day >= 100|Bob") == nullptr);
}

TEST_F(PolicyParser, ExpIntForAttributeList) {
    TEST_DESCRIPTION("Testing that expint logic applies to attribute lists");
    // make sure expint logic applies to attribute lists as well. striving for uniformity
    ASSERT_TRUE(createAttributeList("Alice|Day = 1000#8|Bob") == nullptr);
}

TEST_F(PolicyParser, DuplicateDatesInAttributeListAreIgnored) {
    TEST_DESCRIPTION("Testing that duplicate dates in attribute lists are ignored");
    string a = "|Date = May 10, 2017|Alice";
    unique_ptr<OpenABEAttributeList> attr_list1 = createAttributeList(a + "|Date = July 1, 2015");
    unique_ptr<OpenABEAttributeList> attr_list2 = createAttributeList(a);
    string a1 = attr_list1->toString();
    string a2 = attr_list2->toString();
    ASSERT_TRUE(a1.compare(a2) == 0);
}

TEST_F(PolicyParser, ExpIntNotAllowedInInputAttribute) {
    TEST_DESCRIPTION("Testing that user cannot specify expint as part of an attribute list");
    // make sure user cannot specify expint as part of an attribute
    ASSERT_TRUE(createAttributeList("foo_expint04_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx|bar") == nullptr);
}

TEST_F(PolicyParser, ExpIntNotAllowedInInputPolicy) {
    TEST_DESCRIPTION("Testing that user cannot specify expint as part of a policy");
    ASSERT_TRUE(createPolicyTree("Alice or foo_expint04_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx") == nullptr);
}

class LinearSecretSharing : public ::testing::Test {
 protected:
  virtual void SetUp() {
       verbose = false;
  }
  bool verbose;
};

TEST_F(LinearSecretSharing, TestWithGreaterThan) {
    TEST_DESCRIPTION("Testing LSSS with greater than type policy");
    ASSERT_TRUE(runLSSSTest("Day > 5 and Charlie", "Charlie|Day=7", verbose));
}

TEST_F(LinearSecretSharing, TestWithGreaterThanOrEqual) {
    TEST_DESCRIPTION("Testing LSSS with greater than or equal type policy");
    string attrList = "Day = 7";
    ASSERT_TRUE(runLSSSTest("(Day >= 5)", attrList, verbose));
    ASSERT_FALSE(runLSSSTest("(Day >= 12)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithLessThan) {
    TEST_DESCRIPTION("Testing LSSS with less than operation");
    string attrList = "Day = 17";
    ASSERT_TRUE(runLSSSTest("(Day < 25)", attrList, verbose));
    ASSERT_FALSE(runLSSSTest("(Day < 5)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithLessThanOrEqual) {
    TEST_DESCRIPTION("Testing LSSS with less than or equal type policy");
    string attrList = "Day = 7000";
    ASSERT_TRUE(runLSSSTest("(Day <= 7000)", attrList, verbose));
    ASSERT_FALSE(runLSSSTest("(Day <= 5)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithEquality) {
    TEST_DESCRIPTION("Testing LSSS with just equality type policy");
    string attrList = "Month = 7#4";
    ASSERT_TRUE(runLSSSTest("(Month == 7#4)", attrList, verbose));
    ASSERT_FALSE(runLSSSTest("(Month == 6#4)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestOtherComparisonOps) {
    TEST_DESCRIPTION("Testing LSSS with multiple comparison ops in addition to other attributes in the policy");
    string attrList = "Month = 7#4|Bob|Charlie";
    ASSERT_TRUE(runLSSSTest("(Month<12#4 and Bob)", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("(Month> 2#4 and Charlie)", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("(Month <10#4 and Charlie)", attrList, verbose));
    // make sure this throws an exception. '==' required for equality testing
    ASSERT_ANY_THROW(runLSSSTest("(Month= 2#4 and Charlie)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithSimpleDatePolicies) {
    TEST_DESCRIPTION("Testing LSSS with simple date type policies");
    string attrList = "|Date = December 15, 2015|Bob|Charlie";
    ASSERT_TRUE(runLSSSTest("(Date < January 1, 2017 and Bob)", attrList, verbose));
    ASSERT_FALSE(runLSSSTest("(Date > March 10, 2016 and Charlie)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithIntegerRangeTypePolicies) {
    TEST_DESCRIPTION("Testing LSSS with integer range type policies");
    string attrList = "|Bob|Month = 7#4";
    ASSERT_TRUE(runLSSSTest("(Month in (3#4-15#4) and Bob)", attrList, verbose));
    ASSERT_FALSE(runLSSSTest("(Month in (3#4-5#4) and Bob)", attrList, verbose));
}

TEST_F(LinearSecretSharing, TestWithDateRangeTypePolicies) {
    TEST_DESCRIPTION("Testing LSSS with date range type policies");
    string attrList = "|Date = December 15, 2016|Charlie";
    ASSERT_TRUE(runLSSSTest("((Date = December 10-16, 2016) and Charlie)", attrList, verbose));
    ASSERT_FALSE(runLSSSTest("((Date = December 1-14, 2016) and Charlie)", attrList, verbose));
}

TEST(LSSS, TestCorrectnessOfOrPolicyTree) {
    TEST_DESCRIPTION("Testing correctness of different policy trees");
    // Create attribute list
    string attrList = "|Alice|Bob|Charlie|David";
    bool verbose = true;
    ASSERT_TRUE(runLSSSTest("(Alice or Bob)", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("(Alice and Bob)", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("(Eve or Alice)", attrList, verbose));
    ASSERT_FALSE(runLSSSTest("(Eve or Frank) and Alice", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("((Alice or Bob) and Charlie)", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("((Alice or Bob) and (Charlie or David))", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("((Alice and Bob) or (Charlie and David))", attrList, verbose));
    ASSERT_FALSE(runLSSSTest("(Alice and (Eve or Frank))", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("(Alice or (Eve and Frank))", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("((Eve and Frank) or Alice)", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("(Alice or (Eve or Frank))", attrList, verbose));
    // here we are selecting the shortest path to satisfy the tree (exercising sort logic)
    ASSERT_TRUE(runLSSSTest("((Bob and Charlie) or Alice)", attrList, verbose));
    ASSERT_FALSE(runLSSSTest("(Alice and Eve)", attrList, verbose));
    // test ability to sort
    cout << "* Test ability to sort..." << endl;
    ASSERT_TRUE(runLSSSTest("(Alice or (Bob and Charlie))", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("((Bob and Charlie) or Alice)", attrList, verbose));
}

TEST(LSSS, TestCorrectnessWithDupAttributes) {
    TEST_DESCRIPTION("Testing correctness when duplicate attributes are present");
    string attrList = "|Alice|Bob|Charlie|David";
    bool verbose = true;
    ASSERT_TRUE(runLSSSTest("(Alice or Alice)", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("(Alice and Alice)", attrList, verbose));
    ASSERT_TRUE(runLSSSTest("((Alice and Alice) and Bob)", attrList, verbose));
}

string convertToAttributeListString(vector<string>& attr_list) {
    string a_str = "|";
    for (auto a : attr_list) {
    	a_str += a + "|";
    }
    return a_str;
}

TEST(LSSS, TestCorrectnessOfBalancedAndPolicyTree) {
    TEST_DESCRIPTION("Testing correctness of balanced policy trees");
    // get a comprehensive list of attributes
    string attr_list_good, attr_list_bad;
    vector<string> attrListGood, attrListBad;
    getOpenABEAttributeList(32768, attrListGood);
    attrListBad = attrListGood;
    attrListBad.erase(attrListBad.begin());

    int attrCount = 4;
    string balanced_policy_str = getBalancedOpenABETree(0, attrCount);
    // call function to convert attrListGood to a string sep by '|'
    attr_list_good = convertToAttributeListString(attrListGood);
    ASSERT_TRUE(runLSSSTest(balanced_policy_str, attr_list_good));

#if 0
    attrCount = 8192;
    balanced_policy_str = getBalancedOpenABETree(0, attrCount);
    attr_list_bad = convertToAttributeListString(attrListBad);
    ASSERT_FALSE(runLSSSTest(balanced_policy_str, attr_list_bad));

#ifndef USING_EMSCRIPTEN
    attrCount = 16384;
    balanced_policy_str = getBalancedOpenABETree(0, attrCount);
    ASSERT_TRUE(runLSSSTest(balanced_policy_str, attr_list_good));

    attrCount = 32768;
    balanced_policy_str = getBalancedOpenABETree(0, attrCount);
    ASSERT_TRUE(runLSSSTest(balanced_policy_str, attr_list_good));
#endif
// takes a few minutes to test
//    attrCount = 65536;
//    balanced_policy_str = getBalancedOpenABETree(0, attrCount);
//    getOpenABEAttributeList(attrCount, attrListGood);
//    ASSERT_TRUE(runLSSSTest(balanced_policy_str, attrListGood));

#endif
}

TEST(LSSS, TestCorrectnessOfSkewedAndPolicyTree) {
    TEST_DESCRIPTION("Testing correctness of LSSS on a skewed policy tree");

    string attr_list_good, attr_list_bad;
    // get a comprehensive list of attributes
    vector<string> attrListGood, attrListBad;
    getOpenABEAttributeList(8192, attrListGood);
    attrListBad = attrListGood;
    attrListBad.erase(attrListBad.begin());

    int attrCount = 4;
    string skewed_policy_str = getOpenABEPolicyString(attrCount-1);
    attr_list_good = convertToAttributeListString(attrListGood);
    ASSERT_TRUE(runLSSSTest(skewed_policy_str, attr_list_good));

#if 0
#ifndef USING_EMSCRIPTEN
    attrCount = 8192;
    skewed_policy_str = getOpenABEPolicyString(attrCount-1);
    attr_list_bad = convertToAttributeListString(attrListBad);
    ASSERT_TRUE(runLSSSTest(skewed_policy_str, attr_list_good));
    ASSERT_FALSE(runLSSSTest(skewed_policy_str, attr_list_bad));

    attrCount = 16384;
    getOpenABEAttributeList(attrCount, attrListGood);
    skewed_policy_str = getOpenABEPolicyString(attrCount-1);
    attr_list_good = convertToAttributeListString(attrListGood);
    ASSERT_TRUE(runLSSSTest(skewed_policy_str, attr_list_good));
#endif

#endif
// might take a few minutes to test
//    attrCount = 32768;
//    getOpenABEAttributeList(attrCount, attrListGood);
//    skewed_policy_str = getOpenABEPolicyString(attrCount-1);
//    ASSERT_TRUE(runLSSSTest(skewed_policy_str, attrListGood));

// takes a few minutes to test
//    attrCount = 65536;
//    getOpenABEAttributeList(attrListGood, false);
//    balanced_policy_str = getBalancedOpenABETree(0, attrCount);
//    ASSERT_TRUE(runLSSSTest(attrCount, balanced_policy_str, attrListGood1));
}

/* Note on CPA security tests:
 * Decryption returns OpenABE_NOERROR in either a successful or failed decryption attempt except
 * if an exception is triggered due to invalid inputs. This is by design.
 */

namespace {

class Input {
public:
    Input(OpenABE_SCHEME scheme, const string enc_input,
          const string key, bool expect_pass,
          bool verbose = false) {
        scheme_type    = scheme;
        func_input = enc_input;
        key_input = key;
        expect_pass_ = expect_pass;
        verbose_   = verbose;
    }
    ~Input() {};
    OpenABE_SCHEME scheme_type;
    string func_input, policy_str, key_input;
    vector<string> attr_list;
    bool verbose_, expect_pass_;
};

class CPASecurityForSchemeTest : public ::testing::TestWithParam<Input> {
protected:
    virtual void SetUp() {
        rng_.reset(new OpenABERNG);
        rng_->getRandomBytes(&plaintext, TEST_MSG_LEN);
        MPK = "testMPK";
        MSK = "testMSK";
        AUTH1MPK = "auth1", AUTH1MSK = "auth1MSK";
        AUTH2MPK = "auth2", AUTH2MSK = "auth2MSK";
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
    OpenABEByteString plaintext, plaintext1;
    unique_ptr<OpenABERNG> rng_;
    string MPK, MSK, AUTH1MPK, AUTH1MSK, AUTH2MPK, AUTH2MSK;
};

class CCASecurityForKEMTest : public CPASecurityForSchemeTest {};
class CCASecurityForSchemeTest : public CPASecurityForSchemeTest {};

/* Unit tests for CPA scheme contexts */
TEST_P(CPASecurityForSchemeTest, testWorkingExamples) {
    Input input = GetParam();
    TEST_DESCRIPTION("Testing CPA-secure " + printScheme(input.scheme_type) + " scheme with Key: '" + \
    		input.key_input + "' and Enc: '" + input.func_input + "'");
    OpenABECiphertext ciphertext, ciphertext2;
    cout << "* Testing CPA security for " << printScheme(input.scheme_type) << " schemes..." << endl;
    unique_ptr<OpenABEContextSchemeCPA> schemeContext = OpenABE_createContextABESchemeCPA(input.scheme_type); // OpenABE_SCHEME_CP_WATERS

    // Generate a set of parameters for an ABE authority
    ASSERT_TRUE(schemeContext->generateParams(DEFAULT_BP_PARAM, MPK, MSK) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->exportKey(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->exportKey(MSK, mskBlob) == OpenABE_NOERROR);

    ASSERT_TRUE(schemeContext->deleteKey(MPK) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->deleteKey(MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(schemeContext->loadMasterPublicParams(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->loadMasterSecretParams(MSK, mskBlob) == OpenABE_NOERROR);

    // encrypt under the specified functional input
    unique_ptr<OpenABEFunctionInput> encInput = getEncInput(input.scheme_type, input.func_input);
    ASSERT_TRUE(schemeContext->encrypt(NULL, MPK, encInput.get(), &plaintext, &ciphertext) == OpenABE_NOERROR);

    ciphertext.exportToBytes(ctBlob);
    ciphertext2.loadFromBytes(ctBlob);
    ASSERT_TRUE(ciphertext == ciphertext2);
    // verify header is thesame
    OpenABEByteString hdr1, hdr2;
    ciphertext.getHeader(hdr1);
    ciphertext2.getHeader(hdr2);
    ASSERT_TRUE(hdr1 == hdr2);

    // for both auth1 and auth2
    unique_ptr<OpenABEFunctionInput> keyInput = getKeyInput(input.scheme_type, input.key_input);

    ASSERT_TRUE(schemeContext->keygen((OpenABEFunctionInput *)keyInput.get(), "DecKey", MPK, MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(schemeContext->exportKey("DecKey", skBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->deleteKey("DecKey") == OpenABE_NOERROR);
    ASSERT_TRUE(schemeContext->loadUserSecretParams("DecKey", skBlob) == OpenABE_NOERROR);

    // Decrypt the ciphertext with multiple keys
    ASSERT_TRUE(schemeContext->decrypt(MPK, "DecKey", &plaintext1, &ciphertext2) == OpenABE_NOERROR);

    if (input.verbose_) {
        cout << "Input Plaintext: " << plaintext.toHex() << endl;
    	cout << "Enc Input used: " << input.func_input << endl;
    	cout << "Key Input used: " << input.key_input << endl;
    	cout << "Rec Plaintext: " << plaintext1.toHex() << endl;
    	cout << "Test expected to pass: " << (input.expect_pass_ ? "true" : "false") << endl;
    }
    if(input.expect_pass_) {
        ASSERT_TRUE(plaintext == plaintext1);
    } else {
        ASSERT_FALSE(plaintext == plaintext1);
    }
}

/* Unit test fixture for CCA KEM contexts */
TEST_P(CCASecurityForKEMTest, testWorkingExamples) {
    Input input = GetParam();
    TEST_DESCRIPTION("Testing CCA-secure KEM " + printScheme(input.scheme_type) + " scheme with Key: '" + \
    		input.key_input + "' and Enc: '" + input.func_input + "'");

    OpenABECiphertext ciphertext1, ciphertext2;
    shared_ptr<OpenABESymKey> sym_key(new OpenABESymKey), sym_key1(new OpenABESymKey);
    // , sym_key2(new OpenABESymKey), sym_key3(new OpenABESymKey);

    cout << "* Testing CCA KEM security for " << printScheme(input.scheme_type) << " schemes..." << endl;
    unique_ptr<OpenABEContextCCA> ccaKEMContext = OpenABE_createABEContextForKEM(input.scheme_type);

    // Generate a set of parameters for an ABE authority
    ASSERT_TRUE(ccaKEMContext->generateParams(DEFAULT_BP_PARAM, MPK, MSK) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->exportKey(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->exportKey(MSK, mskBlob) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaKEMContext->deleteKey(MPK) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->deleteKey(MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaKEMContext->loadMasterPublicParams(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->loadMasterSecretParams(MSK, mskBlob) == OpenABE_NOERROR);

    // encrypt under the specified functional input
    unique_ptr<OpenABEFunctionInput> encInput = getEncInput(input.scheme_type, input.func_input);
    // Encrypt a test key using the KEM mode
    ASSERT_TRUE(ccaKEMContext->encryptKEM(rng_.get(), MPK, encInput.get(), DEFAULT_SYM_KEY_BYTES, sym_key, &ciphertext1) == OpenABE_NOERROR);

    // make sure ABE ciphertext and header serialization works correctly
    ciphertext1.exportToBytes(ctBlob);
    ciphertext2.loadFromBytes(ctBlob);
    ASSERT_TRUE(ciphertext1 == ciphertext2);
    // verify header is thesame
    OpenABEByteString hdr1, hdr2;
    ciphertext1.getHeader(hdr1);
    ciphertext2.getHeader(hdr2);
    ASSERT_TRUE(hdr1 == hdr2);

    // for auth1 and auth2
    unique_ptr<OpenABEFunctionInput> keyInput = getKeyInput(input.scheme_type, input.key_input);

    ASSERT_TRUE(ccaKEMContext->generateDecryptionKey((OpenABEFunctionInput *)keyInput.get(), "GoodDecKey1", MPK, MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaKEMContext->exportKey("GoodDecKey1", skBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->deleteKey("GoodDecKey1") == OpenABE_NOERROR);
    ASSERT_TRUE(ccaKEMContext->loadUserSecretParams("GoodDecKey1", skBlob) == OpenABE_NOERROR);

    if (input.verbose_) {
    	cout << "Enc Input used: " << input.func_input << endl;
    	cout << "Key Input used: " << input.key_input << endl;
    	cout << "Test expected to pass: " << (input.expect_pass_ ? "true" : "false") << endl;
    }

    if (input.expect_pass_) {
        ASSERT_TRUE(ccaKEMContext->decryptKEM(MPK, "GoodDecKey1", &ciphertext1, DEFAULT_SYM_KEY_BYTES, sym_key1) == OpenABE_NOERROR);
        ASSERT_TRUE(*sym_key == *sym_key1);
    } else {
        ASSERT_FALSE(ccaKEMContext->decryptKEM(MPK, "GoodDecKey1", &ciphertext1, DEFAULT_SYM_KEY_BYTES, sym_key1) == OpenABE_NOERROR);
        ASSERT_FALSE(*sym_key == *sym_key1);
    }
}


/* Unit test fixture for CCA scheme contexts */
TEST_P(CCASecurityForSchemeTest, testWorkingExamples) {
    Input input = GetParam();
    TEST_DESCRIPTION("Testing CCA-secure scheme " + printScheme(input.scheme_type) + " scheme with Key: '" + \
    		input.key_input + "' and Enc: '" + input.func_input + "'");
    OpenABECiphertext ciphertext1, ciphertext_1, ciphertext2, ciphertext_2;

    cout << "* Testing CCA security for " << printScheme(input.scheme_type) << " schemes..." << endl;
    unique_ptr<OpenABEContextSchemeCCA> ccaSchemeContext = OpenABE_createContextABESchemeCCA(input.scheme_type);

    // Generate a set of parameters for an ABE authority
    ASSERT_TRUE(ccaSchemeContext->generateParams(DEFAULT_BP_PARAM, MPK, MSK) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->exportKey(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->exportKey(MSK, mskBlob) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaSchemeContext->deleteKey(MPK) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->deleteKey(MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaSchemeContext->loadMasterPublicParams(MPK, mpkBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->loadMasterSecretParams(MSK, mskBlob) == OpenABE_NOERROR);

    // encrypt under the specified functional input
    unique_ptr<OpenABEFunctionInput> encInput = getEncInput(input.scheme_type, input.func_input);
    string pt = plaintext.toString();
    ASSERT_TRUE(ccaSchemeContext->encrypt(MPK, encInput.get(), pt, &ciphertext_1, &ciphertext_2) == OpenABE_NOERROR);

    // make sure ABE ciphertext and header serialization works correctly
    ciphertext_1.exportToBytes(ctBlob);
    ciphertext1.loadFromBytes(ctBlob);
    ASSERT_TRUE(ciphertext1 == ciphertext_1);
    // verify header is thesame
    OpenABEByteString hdr1, hdr2;
    ciphertext_1.getHeader(hdr1);
    ciphertext1.getHeader(hdr2);
    ASSERT_TRUE(hdr1 == hdr2);

    // make sure symmetric ciphertext serialization works correctly
    OpenABEByteString ctBlob1, ctBlob2;
    ciphertext_2.exportToBytesWithoutHeader(ctBlob1);
    ciphertext2.loadFromBytesWithoutHeader(ctBlob1);
    ciphertext2.exportToBytesWithoutHeader(ctBlob2);
    ASSERT_TRUE(ctBlob1 == ctBlob2);

    // for auth1 and auth2
    unique_ptr<OpenABEFunctionInput> keyInput = getKeyInput(input.scheme_type, input.key_input);

    ASSERT_TRUE(ccaSchemeContext->keygen((OpenABEFunctionInput *)keyInput.get(), "GoodDecKey1", MPK, MSK) == OpenABE_NOERROR);

    ASSERT_TRUE(ccaSchemeContext->exportKey("GoodDecKey1", skBlob) == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->deleteKey("GoodDecKey1") == OpenABE_NOERROR);
    ASSERT_TRUE(ccaSchemeContext->loadUserSecretParams("GoodDecKey1", skBlob) == OpenABE_NOERROR);

    string pt1;
    if (input.expect_pass_) {
        ASSERT_TRUE(ccaSchemeContext->decrypt(MPK, "GoodDecKey1", pt1, &ciphertext_1, &ciphertext_2) == OpenABE_NOERROR);
        plaintext1 += pt1;
        ASSERT_TRUE(plaintext == plaintext1);
    } else {
        ASSERT_FALSE(ccaSchemeContext->decrypt(MPK, "GoodDecKey1", pt1, &ciphertext_1, &ciphertext_2) == OpenABE_NOERROR);
    }
}

}

INSTANTIATE_TEST_CASE_P(ABETest1, CPASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Alice|Charlie", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|David", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|Eve", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and Alice)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest2, CPASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "uid:567abc", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Alice|Bob", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Bob|Eve", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and Alice)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest3, CPASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "Alice and Date = May 1-10, 2016", "Alice|Date=May 5, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "Date = May 1-10, 2016 and (Alice or Bob)", "Bob|Date=May 8, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and Date = May 1-10, 2016)", "Bob|Eve|Date=May 12, 2016", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Charlie|Date = June 12, 2014", "(Date = June 10-20, 2014 and (Charlie or David))", true),
    Input(OpenABE_SCHEME_KP_GPSW, "David|Date = June 25, 2014", "((David or Bob) and Date = June 21-28, 2014)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|Date = June 30, 2014", "((Alice and Date = June 21-28, 2014) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest4, CCASecurityForKEMTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Alice|Charlie", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|David", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|Eve", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and Alice)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest5, CCASecurityForKEMTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "uid:567abc", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Alice|Bob", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Bob|Eve", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and Alice)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest6, CCASecurityForKEMTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "Alice and Date = May 1-10, 2016", "Alice|Date=May 5, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "Date = May 1-10, 2016 and (Alice or Bob)", "Bob|Date=May 8, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and Date = May 1-10, 2016)", "Bob|Eve|Date=May 12, 2016", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Charlie|Date = June 12, 2014", "(Date = June 10-20, 2014 and (Charlie or David))", true),
    Input(OpenABE_SCHEME_KP_GPSW, "David|Date = June 25, 2014", "((David or Bob) and Date = June 21-28, 2014)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|Date = June 30, 2014", "((Alice and Date = June 21-28, 2014) and Charlie)", false)
));


INSTANTIATE_TEST_CASE_P(ABETest7, CCASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Alice|Charlie", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|David", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and (Charlie or David))", "Bob|Eve", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice or Bob) and Alice)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest8, CCASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "uid:567abc", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Alice|Bob", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice and Bob) or uid:567abc)", "Bob|Eve", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and (Charlie or David)) and Alice", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice or Bob) and Alice)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|uid:567abcdef", "((Alice and Bob) and Charlie)", false)
));

INSTANTIATE_TEST_CASE_P(ABETest9, CCASecurityForSchemeTest,
    ::testing::Values(
    Input(OpenABE_SCHEME_CP_WATERS, "Alice and Date = May 1-10, 2016", "Alice|Date=May 5, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "Date = May 1-10, 2016 and (Alice or Bob)", "Bob|Date=May 8, 2016", true),
    Input(OpenABE_SCHEME_CP_WATERS, "((Alice or Bob) and Date = May 1-10, 2016)", "Bob|Eve|Date=May 12, 2016", false),
    Input(OpenABE_SCHEME_KP_GPSW, "Charlie|Date = June 12, 2014", "(Date = June 10-20, 2014 and (Charlie or David))", true),
    Input(OpenABE_SCHEME_KP_GPSW, "David|Date = June 25, 2014", "((David or Bob) and Date = June 21-28, 2014)", true),
    Input(OpenABE_SCHEME_KP_GPSW, "Alice|Charlie|Date = June 30, 2014", "((Alice and Date = June 21-28, 2014) and Charlie)", false)
));

class SatInput {
public:
    SatInput(const string policy_str, const string attr_list, bool expect_pass) {
    	policy_str_ = policy_str;
    	attr_list_ = attr_list;
        expect_pass_ = expect_pass;
        verbose_   = false;
    }
    ~SatInput() {};
    string policy_str_, attr_list_;
    bool verbose_, expect_pass_;
};

class CheckIfSatisfiedTests : public ::testing::TestWithParam<SatInput> {
protected:
    virtual void SetUp() {}
};

TEST_P(CheckIfSatisfiedTests, testWorkingExamples) {
    SatInput input = GetParam();
    TEST_DESCRIPTION("Checking sat for: '" + input.policy_str_ + "' sat by '" + input.attr_list_ + "'");

    unique_ptr<OpenABEPolicy> policy = createPolicyTree(input.policy_str_);
    ASSERT_TRUE(policy != nullptr);
    unique_ptr<OpenABEAttributeList> attr_list = createAttributeList(input.attr_list_);
    ASSERT_TRUE(attr_list != nullptr);
    pair<bool,int> res = checkIfSatisfied(policy.get(), attr_list.get());
    if (input.expect_pass_) {
        ASSERT_TRUE(res.first);
    } else {
        ASSERT_FALSE(res.first);
    }
}

INSTANTIATE_TEST_CASE_P(CheckSat1, CheckIfSatisfiedTests,
    ::testing::Values(
    // test standard or/and type policy combos
    SatInput("((Alice or Bob) or David)", "Bob", true),
    SatInput("((Alice and Bob) or David)", "Bob|David", true),
    SatInput("(Alice and (Bob or David))", "Bob|David", false),
    SatInput("(Alice and (Bob and David))", "Alice|Bob|David", true),
    SatInput("((Alice or Bob) and David)", "Bob|David", true),
    SatInput("((Alice or Bob) and David)", "Alice|Charlie", false),
    SatInput("((Alice or Bob) and David)", "Alice|David", true),
    SatInput("(David or Charlie)", "Alice|Bob", false),
    SatInput("Bar", "Alice|Bob", false),
    SatInput("Alice", "Alice|Bob", true),
    SatInput("Foor", "Bar", false),
    // test uids
    SatInput("((Alice and Bob) or uid:567abcdef)", "uid:567abcdef|Bob", true),
    SatInput("((Alice or Bob) and uid:567abcdef)", "uid:567abcdef|Bob", true),
    // test integer range
    SatInput("(Floor in (2-5) and Alice)", "Alice|Floor=3", true),
    SatInput("(Floor in (2-5) and Alice)", "Alice|Floor=7", false),
    // test dates and date ranges
    SatInput("(David or Date = January 1-31, 2015)", "David|Bob", true),
    SatInput("(David or Date = January 1-31, 2015)", "Date=January 27, 2015|Bob", true),
    SatInput("(David or Date = January 1-31, 2015)", "Date=March 17, 2015|Bob", false),
    SatInput("Date > January 1, 1971", "Date = January 1, 2010", true),
    SatInput("Date >= January 1, 1971", "Date = January 1, 1971", true),
    SatInput("Date <= January 1, 1971", "Date = January 1, 1975", false),
    SatInput("Date < January 1, 1971", "Date = December 1, 2000", false)
));

int main(int argc, char **argv) {
    int rc;

    InitializeOpenABE();

    ::testing::InitGoogleTest(&argc, argv);
    rc = RUN_ALL_TESTS();

    ShutdownOpenABE();

    return rc;
}
