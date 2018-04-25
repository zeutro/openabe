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
/// \file   test_zml2.cpp
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
LogTestResult(string testName, bool (*testPtr)(), const string fname)
{
    string colorGreen(COLOR_STR_GREEN);
    string colorNormal(COLOR_STR_NORMAL);
    string colorRed(COLOR_STR_RED);

    cout << "Testing if " << testName << "..." << endl;
#if defined(ENABLE_PROFILER)
    if (fname != "") ProfilerStart(fname.c_str());
#endif
    bool testResult = testPtr();
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
Test_InitializeLibrary()
{
  InitializeOpenABE();
  return true;
}

bool
Test_ShutdownLibrary()
{
  ShutdownOpenABE();
  return true;
}

bool
Test_BP_EC_Group()
{
    OpenABE_ERROR err_code = OpenABE_NOERROR;
    OpenABEEllipticCurve egroup(DEFAULT_EC_PARAM);
    OpenABEPairing pgroup(DEFAULT_BP_PARAM);
    OpenABERNG rng;
    OpenABEByteString result;

    try {
        G1 g = pgroup.randomG1(&rng);
        cout << "(BPGroup) g: " << g << endl;

        ZP t = pgroup.randomZP(&rng);
        G1 k = g.exp(t);
        cout << "t: " << t << endl;

        t.serialize(result);
        ZP s = pgroup.initZP();
        s.deserialize(result);
        cout << "s: " << s << endl;
        cout << "(s == t): " << ((s == t) ? "true" : "false") << endl;

        result.clear();
        k.serialize(result);
        cout << "k bytes: " << result.toLowerHex() << endl;
        G1 j = pgroup.initG1();
        j.deserialize(result);
        cout << "(k == j): " << ((k == j) ? "true" : "false") << endl;

        // ECGroup tests
        G_t h = egroup.getGenerator();
        cout << "(ECGroup) h : " << h << endl;

        ZP_t a = egroup.randomZP(&rng);
        G_t A = h.exp(a);
        cout << "A : " << A << endl;
        result.clear();
        A.serialize(result);
        cout << "A bytes: " << result.toLowerHex() << endl;

        G_t B = egroup.initG();
        B.deserialize(result);
        cout << "B: " << B << endl;

        cout << "(A == B): " << ((A == B) ? "true" : "false") << endl;

        result.clear();
        a.serialize(result);
        cout << "a: " << result.toLowerHex() << endl;

        ZP_t b = egroup.initZP();
        b.deserialize(result);
        cout << "b: " << b << endl;
        cout << "(a == b): " << ((a == b) ? "true" : "false") << endl;

    } catch (OpenABE_ERROR& err) {
        cout << "Caught error: " << ::OpenABE_errorToString(err) << " (" << err << ")" << endl;
        err_code = err;
    }

    // Return the result
    return (err_code == OpenABE_NOERROR);
}

int
Test_RunAllTests()
{
    gNumTests = gSuccessfulTests = 0;
    int result = 0;

    // Run through all of the tests for the Zeutro Math Library
    LogTestResult("library can be initialized", Test_InitializeLibrary, "");
    LogTestResult("ECGroup and BPGroup work correctly in memory space", Test_BP_EC_Group, "");
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
    cout << "libopenabe v" << (OpenABE_LIBRARY_VERSION / 100.) << " test utility." << endl << endl;
    cout << "Testing '" << DEFAULT_MATH_LIB << "' with '" << DEFAULT_BP_PARAM << "'" << endl;

    return Test_RunAllTests();
}
