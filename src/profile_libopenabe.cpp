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
///	\file   profile_libopenabe.cpp
///
///	\brief  Tool to profile specific ABE schemes
///
///	\author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <math.h>

#include <openabe/openabe.h>

#define CPABE	"CP"
#define KPABE	"KP"

#define CPA     "cpa"
#define CCA     "cca"

#define KEYGEN_OP  "keygen"
#define ENCRYPT_OP "encrypt"

#define EXIT(msg)	cout << msg << endl; goto CLEANUP

using namespace std;
using namespace oabe;

string getSchemeString(OpenABE_SCHEME scheme_type)
{
  if(scheme_type == OpenABE_SCHEME_CP_WATERS)
    return "CP-ABE";
  else if(scheme_type == OpenABE_SCHEME_KP_GPSW)
    return "KP-ABE";
  else
    throw runtime_error("Invalid scheme type");
}

int profileABE_CPA_KEM(OpenABE_SCHEME scheme_type, string operation, string input_str) {
  cout << "Profiling... " << getSchemeString(scheme_type) << endl;
  unique_ptr<OpenABEContextABE> context = nullptr;
  unique_ptr<OpenABERNG> rng(new OpenABERNG);
  string mpk, msk, auth1mpk, auth1msk, decKey = "decKey";
  shared_ptr<OpenABESymKey> symkey = nullptr;
  std::unique_ptr<OpenABEFunctionInput> keyFuncInput = nullptr, encFuncInput = nullptr;
  unique_ptr<OpenABECiphertext> ciphertext = nullptr;
  int policy_components = 0;

  // Initialize a OpenABEContext structure
  context.reset(OpenABE_createContextABE(&rng, scheme_type));
  if (context == nullptr) {
    EXIT("Unable to create a new context");
  }

  // perform context
  if(scheme_type == OpenABE_SCHEME_CP_WATERS || scheme_type == OpenABE_SCHEME_KP_GPSW) {
    mpk = "MPK";
    msk = "MSK";
    // Generate a set of parameters for an ABE authority
    if (context->generateParams(DEFAULT_BP_PARAM, mpk, msk) != OpenABE_NOERROR) {
        EXIT("Unable to generate params");
    }
  } else {
    EXIT("ERROR: not one of the supported scheme types. See help menu for options.");
  }

  // check the operation now
  if (operation == KEYGEN_OP) {
  // this means we're measuring the size of the keys (for storage)
  if(scheme_type == OpenABE_SCHEME_CP_WATERS) {
    keyFuncInput = std::unique_ptr<OpenABEFunctionInput>(createAttributeList(input_str));
    if (!keyFuncInput) {
      EXIT("ERROR: invalid key input string for CP - expecting attribute list");
    }

    const vector<string> *raw_attrs = ((OpenABEAttributeList*) keyFuncInput.get())->getAttributeList();
    policy_components = raw_attrs->size();


  } else if(scheme_type == OpenABE_SCHEME_KP_GPSW) {
    keyFuncInput = std::unique_ptr<OpenABEFunctionInput>(createPolicyTree(input_str));
    if (!keyFuncInput) {
      EXIT("ERROR: invalid key input string for KP - expecting policy");
    }

    set<string> attr_set = ((OpenABEPolicy *) keyFuncInput.get())->getAttrCompleteSet();
    policy_components = attr_set.size();

  }

  // let's generate the key then export
  context->generateDecryptionKey((OpenABEFunctionInput *)keyFuncInput.get(), "deckey", mpk, msk);

  // export key bytes here
  OpenABEByteString key_str;
  cout << "<=== KEY INPUT ===>\n" << keyFuncInput->toCompactString() << "\n<=== KEY INPUT ===>\n";
  cout << "OpenABE key input attributes: " << policy_components << endl;
  cout << "OpenABE key size: " << key_str.size() << endl;

  } else if(operation == ENCRYPT_OP) {
    // this means we're measuring the size of the ciphertext (for storage)
    if(scheme_type == OpenABE_SCHEME_CP_WATERS) {
      encFuncInput = std::unique_ptr<OpenABEFunctionInput>(createPolicyTree(input_str));
      if (!encFuncInput) {
        EXIT("ERROR: invalid enc input string for CP - expecting policy");
      }

      set<string> attr_set = ((OpenABEPolicy *) encFuncInput.get())->getAttrCompleteSet();
      policy_components = attr_set.size();
    }
    else if(scheme_type == OpenABE_SCHEME_KP_GPSW) {
      // attributes are embedded in the ciphertext
      encFuncInput = std::unique_ptr<OpenABEFunctionInput>(createAttributeList(input_str));
      if (!encFuncInput) {
        EXIT("ERROR: invalid enc input string for KP - expecting attribute list");
      }

      const vector<string> *raw_attrs = ((OpenABEAttributeList*) encFuncInput.get())->getAttributeList();
      policy_components = raw_attrs->size();
    }

    symkey.reset(new OpenABESymKey);
    ciphertext.reset(new OpenABECiphertext);
    context->encryptKEM(nullptr, mpk, encFuncInput.get(), DEFAULT_SYM_KEY_BYTES, symkey, ciphertext.get());

    OpenABEByteString ct_str;
    ciphertext->exportToBytes(ct_str);

    cout << "<=== ENC INPUT ===>\n" << encFuncInput->toCompactString() << "\n<=== ENC INPUT ===>\n";
    cout << "OpenABE enc input attributes: " << policy_components << endl;
    cout << "OpenABE ciphertext size: " << ct_str.size() << endl;
  } else {
    EXIT("ERROR: you specified an invalid or unsupported operation. See help menu for options.");
  }

CLEANUP:
    return 0;
}

int profileABE_CCA_KEM(OpenABE_SCHEME scheme_type, string operation, string input_str) {
    cout << "Profiling... " << getSchemeString(scheme_type) << endl;
    string mpk, msk, auth1mpk, auth1msk, decKey = "decKey";
    std::unique_ptr<OpenABEFunctionInput> keyFuncInput = nullptr, encFuncInput = nullptr;
    shared_ptr<OpenABESymKey> symkey = nullptr;
    unique_ptr<OpenABECiphertext> ciphertext = nullptr;
    unique_ptr<OpenABEContextCCA> ccaContext = nullptr;
    unique_ptr<OpenABEContextSchemeCPA> schemeContext = nullptr;
    unique_ptr<OpenABERNG> rng(new OpenABERNG), rng2(new OpenABERNG);
    int policy_components = 0;

    // initialize a scheme context with the KEM context
    schemeContext = OpenABE_createContextABESchemeCPA(scheme_type);
    if(!schemeContext) {
        EXIT("Unable to create CPA scheme context");
    }

    // initialize a CCA scheme context
    ccaContext.reset(new OpenABEContextGenericCCA(std::move(schemeContext)));
    if(ccaContext == nullptr) {
        EXIT("Unable to create a new CCA KEM context");
    }

    // generate the parameters for the given scheme_type
    if(scheme_type == OpenABE_SCHEME_CP_WATERS || scheme_type == OpenABE_SCHEME_KP_GPSW) {
        mpk = "MPK";
        msk = "MSK";
        // Generate a set of parameters for an ABE authority
        if (ccaContext->generateParams(DEFAULT_BP_PARAM, mpk, msk) != OpenABE_NOERROR) {
            EXIT("Unable to generate params");
        }
    } else {
        EXIT("ERROR: not one of the supported scheme types");
    }

    // check the operation now
    if (operation == KEYGEN_OP) {
        // this means we're measuring the size of the keys (for storage)
        if(scheme_type == OpenABE_SCHEME_CP_WATERS) {
          keyFuncInput = std::unique_ptr<OpenABEFunctionInput>(createAttributeList(input_str));
          if (!keyFuncInput) {
            EXIT("ERROR: invalid key input string for CP/MA - expecting attribute list");
          }

          const vector<string> *raw_attrs = ((OpenABEAttributeList*) keyFuncInput.get())->getAttributeList();
          policy_components = raw_attrs->size();


        } else if(scheme_type == OpenABE_SCHEME_KP_GPSW) {
          keyFuncInput = std::unique_ptr<OpenABEFunctionInput>(createPolicyTree(input_str));
          if (!keyFuncInput) {
            EXIT("ERROR: invalid key input string for KP - expecting policy");
          }

          set<string> attr_set = ((OpenABEPolicy *) keyFuncInput.get())->getAttrCompleteSet();
          policy_components = attr_set.size();

        }

        // let's generate the key then export
        ccaContext->generateDecryptionKey((OpenABEFunctionInput *)keyFuncInput.get(), "deckey", mpk, msk);

        // export key bytes here
        OpenABEByteString key_str;
        ccaContext->exportKey("deckey", key_str);

        cout << "<=== KEY INPUT ===>\n" << keyFuncInput->toCompactString() << "\n<=== KEY INPUT ===>\n";
        cout << "OpenABE key input attributes: " << policy_components << endl;
        cout << "OpenABE key size: " << key_str.size() << endl;

    } else if(operation == ENCRYPT_OP) {
        // this means we're measuring the size of the ciphertext (for storage)
        if(scheme_type == OpenABE_SCHEME_CP_WATERS) {
            encFuncInput = std::unique_ptr<OpenABEFunctionInput>(createPolicyTree(input_str));
            if (!encFuncInput) {
              EXIT("ERROR: invalid enc input string for CP/MA - expecting policy");
            }

            set<string> attr_set = ((OpenABEPolicy *) encFuncInput.get())->getAttrCompleteSet();
            policy_components = attr_set.size();
        }
        else if(scheme_type == OpenABE_SCHEME_KP_GPSW) {
            // attributes are embedded in the ciphertext
            encFuncInput = std::unique_ptr<OpenABEFunctionInput>(createAttributeList(input_str));
            if (!encFuncInput) {
              EXIT("ERROR: invalid enc input string for KP - expecting attribute list");
            }
            const vector<string> *raw_attrs = ((OpenABEAttributeList*) encFuncInput.get())->getAttributeList();
            policy_components = raw_attrs->size();
        }

        symkey.reset(new OpenABESymKey);
        ciphertext.reset(new OpenABECiphertext);
        ccaContext->encryptKEM(rng2.get(), mpk, encFuncInput.get(), DEFAULT_SYM_KEY_BYTES, symkey, ciphertext.get());

        OpenABEByteString ct_str;
        ciphertext->exportToBytes(ct_str);

        cout << "<=== ENC INPUT ===>\n" << encFuncInput->toCompactString() << "\n<=== ENC INPUT ===>\n";
        cout << "OpenABE enc input attributes: " << policy_components << endl;
        cout << "OpenABE ciphertext size: " << ct_str.size() << endl;
    } else {
        EXIT("ERROR: you specified an invalid or unsupported operation. See help menu for options.");
    }

CLEANUP:
    return 0;
}


int main(int argc, const char *argv[])
{
  cout << "Math Library: " << DEFAULT_MATH_LIB << endl;
  if(argc < 5) {
    cout << "OpenABE profiler utility, v" << (OpenABE_LIBRARY_VERSION / 100.) << endl;
    cout << "Usage " << argv[0] << ": [ scheme => 'CP' or 'KP'] [ operation ] [ input ] [ 'cpa' or 'cca']" << endl;
    cout << "\tscheme: the type of ABE scheme to benchmark" << endl;
    cout << "\toperation: 'keygen' or 'encrypt'" << endl;
    cout << "\tinput: an attribute list or policy tree string depending on scheme type" << endl;
    cout << "\tcpa or cca: chosen-plaintext secure vs chosen-ciphertext secure versions" << endl;
    cout << "Profiler:" << endl;
    return -1;
  }

  string schemeType = argv[1];
  string operation  = string( argv[2] );
  string input      = string( argv[3] );
  string secType    = string( argv[4] );

  InitializeOpenABE();

  // get the scheme type
  OpenABE_SCHEME scheme_type;
  if(schemeType == CPABE) {
    /* benchmark with CP-ABE func */
    scheme_type = OpenABE_SCHEME_CP_WATERS;
  }
  else if(schemeType == KPABE) {
    /* benchmark with KP-ABE func */
    scheme_type = OpenABE_SCHEME_KP_GPSW;
  }
  else {
    /* other scheme types  */
    cout << "Invalid scheme type!" << endl;
    return -1;
  }

  try {
    // check the security type
    if(secType == CPA) {
        // run all the CPA tests
        cout << "Running with CPA context" << endl;
        profileABE_CPA_KEM(scheme_type, operation, input);
    }
    else if(secType == CCA) {
        // run all the CCA tests
        cout << "Running with CCA context" << endl;
        profileABE_CCA_KEM(scheme_type, operation, input);
    }
    else {
        cout << "Invalid security type! Expected Argument: '" << CPA << "' or '" << CCA << "'" << endl;
        return -1;
    }
  } catch(OpenABE_ERROR& error) {
      cout << "Caught error: " << ::OpenABE_errorToString(error) << endl;
  }

  ShutdownOpenABE();

  return 0;
}
