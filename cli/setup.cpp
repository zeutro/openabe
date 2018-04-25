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
/// \file   setup.cpp
///
/// \brief  Generate the ABE global system parameters.
///
/// \author J. Ayo Akinyele
///

#include "common.h"

using namespace std;
using namespace oabe;

#define USAGE \
    "usage: [ -s scheme ] [ -p prefix ] -v\n\n" \
    "\t-v : turn on verbose mode\n" \
    "\t-s : scheme types are 'CP' or 'KP'\n" \
    "\t-p : prefix string for generated authority public and secret parameter files (optional)\n\n"

void runSetup(OpenABE_SCHEME scheme_type, string& prefix, string& suffix, bool verbose)
{
    try {
    OpenABEByteString mpkBlob, mskBlob;
    string mpkFile = MPK_ID + suffix, mskFile = MSK_ID + suffix;
    if(prefix != "") {
      mpkFile = prefix + mpkFile;
      mskFile = prefix + mskFile;
    }

    // abeSetup(scheme_type, prefix, mpkBlob, mskBlob);
    std::unique_ptr<OpenABEContextSchemeCCA> schemeContext = nullptr;
    // default parameters
    string mpkID = MPK_ID, mskID = MSK_ID;
    if (prefix != "") {
      mpkID   = prefix + mpkID;
      mskID   = prefix + mskID;
    }
    // Initialize a OpenABEContext structure
    schemeContext = OpenABE_createContextABESchemeCCA(scheme_type);
    if (schemeContext == nullptr) {
      cerr << "unable to create a new context" << endl;
      return;
    }

    // Generate a set of parameters for an ABE authority
    if (schemeContext->generateParams(DEFAULT_PARAMETER_STRING, mpkID, mskID) != OpenABE_NOERROR) {
      cerr << "unable to generate parameters" << endl;
      return;
    }

    // don't password protect the master public parameters (not necessary here)
    if (schemeContext->exportKey(mpkID, mpkBlob) != OpenABE_NOERROR) {
      cerr << "unable to export public parameters" << endl;
      return;
    }

    if (schemeContext->exportKey(mskID, mskBlob) != OpenABE_NOERROR) {
      cerr << "unable to export master secret parameters" << endl;
      return;
    }

    //		cout << "MPK: " << mpkBlob.toHex() << endl;
    //		cout << "MSK: " << mskBlob.toHex() << endl;
    cout << "writing " << mpkBlob.size() << " bytes to " << mpkFile << endl;
    WriteToFile(mpkFile.c_str(), MPK_BEGIN_HEADER + Base64Encode(mpkBlob.getInternalPtr(), mpkBlob.size()) + MPK_END_HEADER);
    cout << "writing " << mskBlob.size() << " bytes to " << mskFile << endl;
    WriteToFile(mskFile.c_str(), MSK_BEGIN_HEADER + Base64Encode(mskBlob.getInternalPtr(), mskBlob.size()) + MSK_END_HEADER);

    } catch (OpenABE_ERROR& error) {
    	cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    	return;
    }

    return;
}

int main(int argc, char **argv)
{
    // if interactive flag set, then enter password via stdin (instead of command line)
    bool verbose_flag = false;
    string scheme_type = "", prefix = "", suffix = "";
    int c;
    if(argc <= 1) {
        cout << OpenABE_CLI_STRING << "system setup utility, v" << (OpenABE_LIBRARY_VERSION / 100.) << endl;
        fprintf(stderr, USAGE);
        return -1;
    }

    while((c = getopt(argc, argv, "vs:p:")) != -1) {
    	switch(c) {
          case 's': scheme_type = string(optarg); break;
          case 'p': prefix = string(optarg); break;
          case 'v': verbose_flag = true; break;
          case '?': fprintf(stderr, USAGE);
          default:  cout<<endl; exit(-1);
    	}
    }
    // check prefix ending
    addNameSeparator(prefix);
    // validate scheme type
    OpenABE_SCHEME scheme = checkForScheme(scheme_type, suffix);
    if (scheme == OpenABE_SCHEME_NONE) {
        cerr << "selected an invalid scheme type. Try again with -s option." << endl;
    	return -1;
    } else if (scheme == OpenABE_SCHEME_PK_OPDH) {
        cerr << "PK encryption does not require setup. Can simply proceed with keygen." << endl;
        return -1;
    }

    InitializeOpenABE();

    // KP or CP
    runSetup(scheme, prefix, suffix, verbose_flag);

    ShutdownOpenABE();

    return 0;
}
