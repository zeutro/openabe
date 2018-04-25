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
/// \file   test_zml1.cpp
///
/// \brief  Unit testing utility for Zeutro Math Library
///
/// \author J. Ayo Akinyele
///

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <openabe/utils/zbenchmark.h>
#if defined(ENABLE_PROFILER)
#include <gperftools/profiler.h>
#endif

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

#define COLOR_STR_GREEN   "\033[32m"
#define COLOR_STR_NORMAL  "\033[0m"
#define COLOR_STR_RED     "\033[31m"

#define EXIT(msg)   cout << msg << endl; goto CLEANUP
#define NUM_PAIRING_TESTS           10
#define ASSERT_RESULT(condition, msg)   if(condition) { \
    cout << "FAIL: " << msg << endl; \
    return false; }

// Global test counters
uint32_t    gNumTests        = 0;
uint32_t    gSuccessfulTests = 0;

//////////
// Utility routines
//////////

void
LogTestResult(string testName, bool (*testPtr)(const string& arg),
              const string fname, const string curve_param = "")
{
    string colorGreen(COLOR_STR_GREEN);
    string colorNormal(COLOR_STR_NORMAL);
    string colorRed(COLOR_STR_RED);
    string curve_id(curve_param);

    cout << "Testing if " << testName << "..." << endl;
#if defined(ENABLE_PROFILER)
    if (fname != "") ProfilerStart(fname.c_str());
#endif
    bool testResult = testPtr(curve_id);
#if defined(ENABLE_PROFILER)
    if (fname != "") ProfilerStop();
#endif
    if (testResult == true) {
        cout << "\t" << colorGreen << "[PASS]"  << colorNormal << endl;
        gSuccessfulTests++;
    } else {
        cout << colorRed << "\t[FAIL]" << colorNormal << endl;
    }

    gNumTests++;
}

bool
Test_InitializeLibrary(const string& arg)
{
  InitializeOpenABE();
  return true;
}

bool
Test_ShutdownLibrary(const string& arg)
{
  ShutdownOpenABE();
  return true;
}

bool
Test_ZP_operations(const string& curve_id)
{
    OpenABE_ERROR result = OpenABE_NOERROR;
    OpenABEPairing pgroup(curve_id);
//    OpenABEPairing pgroup(DEFAULT_BP_PARAM);
//    OpenABERNG rng;
    std::string seed;
    OpenABEByteString entropy, hashSeed;
    entropy.fromHex("ff00de1f793fa5307ea2c3809a457c1cce25ed9eba2c320e7a1bd5fb72aeeeaa");
    cout << "Entropy len: " << entropy.size() << endl;
    sha256ToHex(seed, "the seed");
    hashSeed.fromHex(seed);
    OpenABECTR_DRBG rng(entropy);
    rng.setSeed(hashSeed);
    int large_num = 10000;

    try {
        ZP a;
        pgroup.initZP(a, 1234567890);

        int len = 0;
        char *str = zml_bignum_toHex(pgroup.order, &len);
        string s0 = string(str, len);
        zml_bignum_safe_free(str);
        cout << "order: " << s0 << endl;

        cout << "Output: a = " << a << endl;
        cout << "Negation: -a = " << -a << endl;
        cout << "a + -a = " << (a + -a) << endl;

        ZP c = a;
        c.multInverse();
        cout << "c = inv(a) : " << c << endl;
        cout << "a * c = " << (a * c) << endl;

        //OpenABERNG rng;
        for (int i = 0; i < large_num; i++) {
            ZP tmp = pgroup.randomZP(&rng);
        }
        ZP x = pgroup.randomZP(&rng);
        cout << "x : " << x << endl;

        // test writing out bytestrings
        OpenABEByteString z1, z2;

        z1 = x.getByteString();
        cout << "x in raw bin: " << z1.toHex() << endl;

        string s = x.getBytesAsString();
        cout << "x in str hex: " << s << endl;

        // serialize
        x.serialize(z2);
        cout << "x out: " << z2.toLowerHex() << endl;
        ZP x1;
        pgroup.initZP(x1, 0);
        x1.deserialize(z2);
        if (x == x1) {
            cout << "ser/des OK. x = " << x1 << endl;
        } else {
            cout << "FAILED to deserialize correctly!" << endl;
        }

        ZP y = pgroup.randomZP(&rng);

        ZP z = x * y;
        cout << "z = x * y => " << z << endl;
        ZP t = z / y;
        cout << "(z / y) == x ? " << ((t == x) ? "true" : "false") << endl;
        ZP u = z / x;
        cout << "(z / x) == y ? " << ((u == y) ? "true" : "false") << endl;

        // test division by constants
        cout << "x / 2 = " <<  x / ZP(2) << endl;
        cout << "x / -2 = " <<  x / ZP(-2) << endl;

        cout << "power(x, 1234567890) => " << power(x, 1234567890) << endl;
        cout << "power(x, a) => " << power(x, a) << endl;

        ZP zero, one, two;
        pgroup.initZP(zero, 0);
        pgroup.initZP(one, 1);
        pgroup.initZP(two, 2);

        ZP z0 = (zero - one) / (two - one);
        // ZP z0 = ((ZP(0) - ZP(1)) / (ZP(2) - ZP(1)));
        cout << "z0: " << z0 << endl;

        if (z0.ismember())
            cout << "z0 is a member" << endl;
        else
            cout << "z0 is NOT a member" << endl;


    } catch (OpenABE_ERROR& err) {
        cout << "Caught error: " << ::OpenABE_errorToString(err) << " (" << err << ")" << endl;
        result = err;
    }

    // Return the result
    return (result == OpenABE_NOERROR);
}

bool
Test_G1_operations(const string& curve_id)
{
    Benchmark benchOps;
    OpenABE_ERROR result = OpenABE_NOERROR;
    OpenABEPairing pgroup(DEFAULT_BP_PARAM);
//    OpenABERNG rng;
    std::string seed;
    OpenABEByteString entropy, hashSeed;
    entropy.fromHex("ff00de1f793fa5307ea2c3809a457c1cce25ed9eba2c320e7a1bd5fb72aeeeaa01e6d0");
    sha256ToHex(seed, "the seed");
    hashSeed.fromHex(seed);
    OpenABECTR_DRBG rng(entropy);
    rng.setSeed(hashSeed);

    try {
        G1 g = pgroup.randomG1(&rng);
        cout << "g => " << g << endl;

        G1 h = g * g;
        cout << "(mul) h = (g * g) => " << h << endl;

        G1 k = -h;
        cout << "(negation) k = -h: " << k << endl;

        // expecting this to be true! (if not, what's wrong?)
        G1 i = h / g;
        cout << "(div) i == (h / g) => " << ((i == g) ? "true" : "false") << endl;
        cout << "i => " << i << endl;

        ZP r = pgroup.randomZP(&rng);
        benchOps.start();
        G1 a = g.exp(r);
        benchOps.stop();
        cout << "(exp) a = (g^r) => " << a << endl;
        cout << "(G1 exp time) " << benchOps.computeTimeInMilliseconds() << " ms" << endl;
        OpenABEByteString tmp;
        a.serialize(tmp);
        cout << "serialized a => " << tmp.toHex() << endl;

        G1 b = pgroup.initG1();
        b.deserialize(tmp);
        cout << "b (rec a) => " << b << endl;

        cout << "a == b ? " << ((a == b) ? "true" : "false") << endl;

        cout << "(membership check) a ";
        if (a.ismember(pgroup.order)) {
            cout << "is a member!" << endl;
        } else {
            cout << "is NOT a member!" << endl;
        }

        // test hashing to G1
        OpenABEByteString f;
        rng.getRandomBytes(&f, HASH_LEN);
        G1 F = pgroup.hashToG1(f, "hello world!");
        cout << "(hash to G1) F => " << F << endl;

        G1 H = pgroup.hashToG1(f, "hello world1");
        cout << "(hash to G1) H => " << H << endl;

        if (F != H) {
            cout << "Successful hashed two similar strings to different points." << endl;
        } else {
            cout << "COLLISION ERROR! Same value for different strings?!" << endl;
        }

    } catch (OpenABE_ERROR& err) {
        cout << "Caught error: " << ::OpenABE_errorToString(err) << " (" << err << ")" << endl;
        result = err;
    }

    // Return the result
    return (result == OpenABE_NOERROR);
}

bool
Test_G2_operations(const string& curve_id)
{
    Benchmark benchOps;
    OpenABE_ERROR result = OpenABE_NOERROR;
    OpenABEPairing pgroup(DEFAULT_BP_PARAM);
//    OpenABERNG rng;
    std::string seed;
    OpenABEByteString entropy, hashSeed;
    entropy.fromHex("ff00de1f793fa5307ea2c3809a457c1cce25ed9eba2c320e7a1bd5fb72aeeeaa01e6d0");
    sha256ToHex(seed, "the seed");
    hashSeed.fromHex(seed);
    OpenABECTR_DRBG rng(entropy);
    rng.setSeed(hashSeed);

    try {
        G2 g = pgroup.randomG2(&rng);
        cout << "g => " << g << endl;

        G2 h = g * g;
        cout << "(mul) h = (g * g) => " << h << endl;

        G2 k = -h;
        cout << "(negation) k = -h: " << k << endl;

        // expecting this to be true! (if not, what's wrong?)
        G2 i = h / g;
        cout << "(div) i == (h / g) => " << ((i == g) ? "true" : "false") << endl;
        cout << "i => " << i << endl;

        ZP r = pgroup.randomZP(&rng);
        benchOps.start();
        G2 a = g.exp(r);
        benchOps.stop();
        cout << "(exp) a = (g^r) => " << a << endl;
        cout << "(G2 exp time) " << benchOps.computeTimeInMilliseconds() << " ms" << endl;

        OpenABEByteString tmp;
        a.serialize(tmp);
        cout << "serialized a => " << tmp.toHex() << endl;

        G2 b = pgroup.initG2();
        b.deserialize(tmp);
        cout << "b (rec a) => " << b << endl;

        cout << "a == b ? " << ((a == b) ? "true" : "false") << endl;

        cout << "(membership check) a ";
        if (a.ismember(pgroup.order)) {
            cout << "is a member!" << endl;
        } else {
            cout << "is NOT a member!" << endl;
        }

    } catch (OpenABE_ERROR& err) {
        cout << "Caught error: " << ::OpenABE_errorToString(err) << " (" << err << ")" << endl;
        result = err;
    }

    // Return the result
    return (result == OpenABE_NOERROR);
}

bool
Test_GT_operations(const string& curve_id)
{
    Benchmark benchOps;
    OpenABE_ERROR result = OpenABE_NOERROR;
    OpenABEPairing pgroup(DEFAULT_BP_PARAM);
//    OpenABERNG rng;
    std::string seed;
    OpenABEByteString entropy, hashSeed;
    entropy.fromHex("ff00de1f793fa5307ea2c3809a457c1cce25ed9eba2c320e7a1bd5fb72aeeeaa01e6d0");
    sha256ToHex(seed, "the seed");
    hashSeed.fromHex(seed);
    OpenABECTR_DRBG rng(entropy);
    rng.setSeed(hashSeed);

    try {
        G1 g1 = pgroup.randomG1(&rng);
        cout << "g1 => " << g1 << endl;

        G2 g2 = pgroup.randomG2(&rng);
        cout << "g2 => " << g2 << endl;

        GT gt = pgroup.pairing(g1, g2);
        cout << "gt => " << gt << endl;

        GT h = gt * gt;
        cout << "(mul) h = (gt * gt) => " << h << endl;

        GT k = -h;
        cout << "(negation) k = -h: " << k << endl;

        // expecting this to be true! (if not, what's wrong?)
        GT i = h / gt;
        cout << "(div) i == (h / gt) => " << ((i == gt) ? "true" : "false") << endl;
        cout << "i => " << i << endl;

        ZP r = pgroup.randomZP(&rng);
        benchOps.start();
        GT a = gt.exp(r);
        benchOps.stop();
        cout << "(GT exp time) " << benchOps.computeTimeInMilliseconds() << " ms" << endl;
        cout << "(exp) a = (gt^r) => " << a << endl;

        OpenABEByteString tmp;
        a.serialize(tmp);
        cout << "serialized a => " << tmp.toHex() << endl;

        GT b = pgroup.initGT();
        b.deserialize(tmp);
        cout << "b (rec a) => " << b << endl;

        cout << "a == b ? " << ((a == b) ? "true" : "false") << endl;

        cout << "(membership check) a ";
        if (a.ismember(pgroup.order)) {
            cout << "is a member!" << endl;
        } else {
            cout << "is NOT a member!" << endl;
        }
    } catch (OpenABE_ERROR& err) {
        cout << "Caught error: " << ::OpenABE_errorToString(err) << " (" << err << ")" << endl;
        result = err;
    }

    // Return the result
    return (result == OpenABE_NOERROR);
}


bool
Test_BP_operations(const string& curve_id)
{
    Benchmark benchOps;
    OpenABE_ERROR result = OpenABE_NOERROR;
    OpenABEPairing pgroup(DEFAULT_BP_PARAM);
    OpenABEByteString entropy;
    entropy.fromHex("ff12de1f793fa5307ea2c3809a457c1cce25ed9eba2c320e7a1bd5fb72aeeeaa01e6d0");
    OpenABERNG rng;
    //OpenABECTR_DRBG rng(entropy);

    try {
        // pairing test
        G1 g1 = pgroup.randomG1(&rng);
        cout << "g1 => " << g1 << endl;

        G2 g2 = pgroup.randomG2(&rng);
        cout << "g2 => " << g2 << endl;

        ZP a1 = pgroup.randomZP(&rng);
        ZP b1 = pgroup.randomZP(&rng);
        G1 g = g1.exp(a1);
        G2 h = g2.exp(b1);

        benchOps.start();
        GT gta = pgroup.pairing(g, h);
        benchOps.stop();
        cout << "gt => e(g1^a, g2^b) : " << gta << endl;
        cout << "(pair time) " << benchOps.computeTimeInMilliseconds() << " ms" << endl;

        GT gtb = pgroup.pairing(g1, g2).exp(a1 * b1);
        cout << "bp is correct: e(g1^a, g2^b) == e(g1, g2)^(ab) => " << (gta == gtb ? "true" : "false") << endl;

        // pairing and multi-pairing tests
        vector<G1> g1s;
        vector<G2> g2s;
        // Generate a random element of G1, G2 and ZP
        G1 p0 = pgroup.randomG1(&rng);
        G1 p1 = pgroup.randomG1(&rng);
        G2 q0 = pgroup.randomG2(&rng);
        G2 q1 = pgroup.randomG2(&rng);

        GT gt1 = pgroup.pairing(p0, q0) * pgroup.pairing(p1, q1);
        // cout << "pairing => " << gt1 << endl;

        g1s.push_back(p0);
        g1s.push_back(p1);
        g2s.push_back(q0);
        g2s.push_back(q1);

        GT gt2 = pgroup.initGT();
        benchOps.start();
        pgroup.multi_pairing(gt2, g1s, g2s);
        benchOps.stop();
        cout << "(multi pair time) " << benchOps.computeTimeInMilliseconds() << " ms" << endl;

        // cout << "pairing prod => " << gt2 << endl;

        if (gt1 == gt2) {
            cout << "First test is a SUCCESS!" << endl;
        } else {
            cout << "Values don't match!!" << endl;
        }

        g1s.clear();
        g2s.clear();
        ZP a = pgroup.randomZP(&rng);
        ZP b = pgroup.randomZP(&rng);
        ZP c = pgroup.randomZP(&rng);
        ZP d = pgroup.randomZP(&rng);

        g1s.push_back(p0.exp(a));
        g1s.push_back(p0.exp(b));

        g2s.push_back(q0.exp(c));
        g2s.push_back(q0.exp(d));

        // e(g1^a, g2^c) * e(g1^b, g2^d)
        GT gt3 = pgroup.pairing(g1s.at(0), g2s.at(0)) * pgroup.pairing(g1s.at(1), g2s.at(1));

        GT gt4 = pgroup.initGT();
        pgroup.multi_pairing(gt4, g1s, g2s);

        if (gt3 == gt4) {
            cout << "Second test is a SUCCESS!" << endl;
        } else {
            cout << "Values don't match!" << endl;
        }
        cout << "Test complete!" << endl;
        // hash to G1 and G2
    } catch (OpenABE_ERROR& err) {
        cout << "Caught error: " << ::OpenABE_errorToString(err) << " (" << err << ")" << endl;
        result = err;
    }

    // Return the result
    return (result == OpenABE_NOERROR);
}

int
Test_RunAllTests(const string& curve_id)
{
    gNumTests = gSuccessfulTests = 0;
    int result = 0;

    // Run through all of the tests for the Zeutro Math Library
    LogTestResult("library can be initialized", Test_InitializeLibrary, "");
    LogTestResult("ZP operations are correct", Test_ZP_operations, "Test_ZP_operations", curve_id);

//    LogTestResult("G1 operations are correct", Test_G1_operations, "Test_G1_operations", curve_id);
//    LogTestResult("G2 operations are correct", Test_G2_operations, "Test_G2_operations", curve_id);
//    LogTestResult("GT operations are correct", Test_GT_operations, "Test_GT_operations", curve_id);
//    LogTestResult("Pairing operations are correct", Test_BP_operations, "Test_BP_operations", curve_id);
    // The following test must be last!
    LogTestResult("library can be shut down", Test_ShutdownLibrary, "");

    // Summarize test results
    if (gSuccessfulTests < gNumTests) {
        cout << endl << "ERROR: SOME TESTS FAILED" << endl;
        result = 1;
    }

    cout << endl << gSuccessfulTests << " out of " << gNumTests << " tests passed." << endl << endl;
    return result;
}

int main(int argc, char **argv)
{
  string CURVE_ID = DEFAULT_BP_PARAM;
  cout << "libopenabe v" << (OpenABE_LIBRARY_VERSION / 100.) << " test utility." << endl << endl;
  if (argc == 2) {
      CURVE_ID = string(argv[1]);
  }

  if (CURVE_ID.compare("BN_P254") == 0 || CURVE_ID.compare("BN_P382") == 0) {
      cout << "Testing '" << DEFAULT_MATH_LIB << "' with '" << CURVE_ID << "'" << endl;
      return Test_RunAllTests(CURVE_ID);
  } else {
      cerr << "Invalid curve specified: " << CURVE_ID << endl;
      return -1;
  }
}
