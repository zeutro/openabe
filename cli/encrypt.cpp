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
/// \file   encrypt.cpp
///
/// \brief  OpenABE encryption utility.
///
/// \author J. Ayo Akinyele
///

#include "common.h"

using namespace std;
using namespace oabe;

#define USAGE \
    "usage: [ -s scheme ] [ -p prefix ] [ -e encryption input ] [ -i input ] [ -o output ] -v\n\n" \
    "\t-v : turn on verbosity\n" \
    "\t-s : scheme types are 'PK', 'CP' or 'KP'\n" \
    "\t-e : sender key Id for PK, policy string for 'CP' or attribute list for 'KP'\n" \
    "\t-r : recipient key Id for PK\n" \
    "\t-i : input file\n" \
    "\t-o : output file for ciphertext\n" \
    "\t-p : prefix for generated authority public and secret parameter files (optional)\n\n" \

bool getPublicKey(OpenABEByteString& publicKey, string& id, string& suffix) {
    const string pubKeyFile = id + ".pk" + suffix;
    publicKey = ReadFile(pubKeyFile.c_str());
    if (publicKey.size() == 0) {
        cerr << "public key file not encoded properly in: " << pubKeyFile << endl;
        return false;
    }
    return true;
}

void runPkEncrypt(string& suffix, string& sender_id, string& recipient_id,
                  string& inputStr, string& ciphertextFile, bool verbose) {

    OpenABE_ERROR result = OpenABE_NOERROR;
    // load public key file for the recipient
    OpenABEByteString send_PublicKey, recp_PublicKey, ctBlob;
    try {
        if (!getPublicKey(send_PublicKey, sender_id, suffix)) {
            return;
        }
        if (!getPublicKey(recp_PublicKey, recipient_id, suffix)) {
            return;
        }

        unique_ptr<OpenABEContextSchemePKE> schemeContext = OpenABE_createContextPKESchemeCCA(OpenABE_SCHEME_PK_OPDH);
        if (schemeContext == nullptr) {
            cerr << "unable to create a new context" << endl;
            return;
        }

        // Generate a set of parameters for an ABE authority
        if ( (result = schemeContext->generateParams(DEFAULT_NIST_PARAM_STRING)) != OpenABE_NOERROR) {
            cerr << "unable to generate curve parameters: " << DEFAULT_NIST_PARAM_STRING << endl;
            throw result;
        }

        string sen_pkID = "public_" + sender_id;
        string rec_pkID = "public_" + recipient_id;
        if ((result = schemeContext->loadPublicKey(sen_pkID, send_PublicKey)) != OpenABE_NOERROR) {
            cerr << "unable to load the sender's public key: " << rec_pkID << endl;
            throw result;
        }

        if ((result = schemeContext->loadPublicKey(rec_pkID, recp_PublicKey)) != OpenABE_NOERROR) {
            cerr << "unable to load the recipient's public key: " << rec_pkID << endl;
            throw result;
        }

        unique_ptr<OpenABECiphertext> ciphertext(new OpenABECiphertext);
        if ((result = schemeContext->encrypt(nullptr, rec_pkID, sen_pkID, inputStr, ciphertext.get())) != OpenABE_NOERROR) {
            cerr << "error while trying to encrypt input file" << endl;
            throw result;
        }

        // write ciphertext out
        ciphertext->exportToBytes(ctBlob);
        string ctBlobStr = CT2_BEGIN_HEADER;
        ctBlobStr += NL + Base64Encode(ctBlob.getInternalPtr(), ctBlob.size()) + NL;
        ctBlobStr += CT2_END_HEADER;
        ctBlobStr += NL;

        if (verbose) {
            cout << "writing " << ctBlob.size() << " bytes" << endl;
        }
        WriteToFile(ciphertextFile.c_str(), ctBlobStr);

    } catch (OpenABE_ERROR& error) {
        cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    }

    return;
}


void runAbeEncrypt(OpenABE_SCHEME scheme_type, string& prefix, string& suffix, string& func_input,
    	       string& inputStr, string& ciphertextFile, bool verbose)
{
  OpenABE_ERROR result = OpenABE_NOERROR;
  std::unique_ptr<OpenABEContextSchemeCCA> schemeContext = nullptr;
  std::unique_ptr<OpenABEFunctionInput> funcInput = nullptr;
  string mpkID = MPK_ID;
  string mpkFile = MPK_ID + suffix;
  if(prefix != "") {
    mpkFile = prefix + mpkFile;
  }

  OpenABEByteString ct1Blob, ct2Blob, mpkBlob;

    try {
    // Initialize a OpenABEContext structure
    schemeContext = OpenABE_createContextABESchemeCCA(scheme_type);
    if (schemeContext == nullptr) {
      cerr << "unable to create a new context" << endl;
      return;
    }

    // next, get the functional input for encryption (based on scheme type)
    if (scheme_type == OpenABE_SCHEME_KP_GPSW) {
      funcInput = createAttributeList(func_input);
    } else if(scheme_type == OpenABE_SCHEME_CP_WATERS) {
      funcInput = createPolicyTree(func_input);
    }
    ASSERT(funcInput != nullptr, OpenABE_ERROR_INVALID_INPUT);

    // for KP and CP, we only have to do this once
    mpkBlob = ReadFile(mpkFile.c_str());
    if (mpkBlob.size() == 0) {
      cerr << "master public parameters not encoded properly." << endl;
      return;
    }

    if ((result = schemeContext->loadMasterPublicParams(mpkID, mpkBlob)) != OpenABE_NOERROR) {
      cerr << "unable to load the master public parameters" << endl;
      throw result;
    }

    std::unique_ptr<OpenABECiphertext> ciphertext1(new OpenABECiphertext);
    std::unique_ptr<OpenABECiphertext> ciphertext2(new OpenABECiphertext);
    if ((result = schemeContext->encrypt(mpkID, funcInput.get(), inputStr, ciphertext1.get(), ciphertext2.get())) != OpenABE_NOERROR) {
      cerr << "error occurred during encryption" << endl;
      throw result;
    }

    // write to disk
    ciphertext1->exportToBytes(ct1Blob);
    ciphertext2->exportToBytesWithoutHeader(ct2Blob);
    string ctBlobStr = CT1_BEGIN_HEADER;
    ctBlobStr += NL + Base64Encode(ct1Blob.getInternalPtr(), ct1Blob.size()) + NL;
    ctBlobStr += CT1_END_HEADER;
    ctBlobStr += NL;
    ctBlobStr += CT2_BEGIN_HEADER;
    ctBlobStr += NL + Base64Encode(ct2Blob.getInternalPtr(), ct2Blob.size()) + NL;
    ctBlobStr += CT2_END_HEADER;
    ctBlobStr += NL;

    if(verbose) { cout << "writing " << ct2Blob.size() << " bytes" << endl; }
    WriteToFile(ciphertextFile.c_str(), ctBlobStr);

    } catch (OpenABE_ERROR & error) {
    	cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    }

    return;
}

int main(int argc, char **argv)
{
  if (argc <= 1) {
    cout << OpenABE_CLI_STRING << "encryption utility, v" << (OpenABE_LIBRARY_VERSION / 100.) << endl;
    fprintf(stderr, USAGE);
    exit(-1);
  }
  int opt;
  string func_input = "", input_file = "", prefix = "", suffix = "", scheme_type = "";
  string mpk_file, recipient_id = "", ciphertext_file;
  string inputStr;

  bool verbose = false;
  while ((opt = getopt(argc,argv,"p:s:i:e:o:r:v")) != EOF)
  {
    switch(opt)
    {
      case 'p': prefix = string(optarg); break;
      case 's': scheme_type = string(optarg); break;
      case 'i': cout << "input file: " << optarg << endl; input_file = optarg; break;
      case 'e': func_input = string(optarg); break;
      case 'r': recipient_id = string(optarg); break;
      case 'o': ciphertext_file = optarg; break;
      case 'v': verbose = true; break;
      case '?': fprintf(stderr, USAGE);
      default: cout<<endl; exit(-1);
    }
  }
  // check prefix ending
  addNameSeparator(prefix);
  // validate scheme type
  OpenABE_SCHEME scheme = checkForScheme(scheme_type, suffix);
  if(scheme == OpenABE_SCHEME_NONE) {
      cerr << "selected an invalid scheme type. Try again with -s option.\n";
      return -1;
  }

  try {
    getFile(inputStr, input_file);
    size_t inputLen = inputStr.size();
    if (inputLen == 0 || inputLen > MAX_FILE_SIZE) {
      cerr << "input file is either empty or too big! Can encrypt up to 4GB files." << endl;
      return -1;
    }
  } catch(const std::ios_base::failure& e) {
    cerr << e.what() << endl;
    return -1;
  }

  if (verbose) {
    cout << "read " << inputStr.size() << " bytes from " << input_file << endl;
  }

  // see if suffix has been added to the ciphertext filename
  addFileExtension(ciphertext_file, suffix);

  InitializeOpenABE();

  if (scheme == OpenABE_SCHEME_PK_OPDH) {
    string sender_id = func_input;
    if (sender_id == "" || recipient_id == "") {
        cerr << "missing sender ID (-e option) and/or recipient ID (-r option)" << endl;
        goto cleanup;
    }
    cout << "sender ID: " << sender_id << endl;
    cout << "recipient ID: " << recipient_id << endl;
    runPkEncrypt(suffix, sender_id, recipient_id, inputStr, ciphertext_file, verbose);
  } else {
    cout << "encryption functional input: "<< func_input << endl;
    runAbeEncrypt(scheme, prefix, suffix, func_input, inputStr, ciphertext_file, verbose);
  }

cleanup:
  ShutdownOpenABE();

  return 0;
}
