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
///	\file   test_policy.cpp
///
///	\brief  Functional testing utility for OpenABE. This executable is capable
///         of running all functional tests, depending on user settings.
///
///	\author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>

#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

bool TestPolicy(const char *str)
{
  string policy_str(str);
  std::unique_ptr<OpenABEPolicy> policy = createPolicyTree(policy_str);

  if(policy != nullptr) {
    cout << "Policy Full: " << policy->toString() << endl;
    cout << "Policy Compact: " << policy->toCompactString() << endl;

    std::unique_ptr<OpenABEPolicy> policy2 = nullptr;
    policy2.reset(policy->clone());
    cout << "Policy2 Full: " << policy2->toString() << endl;
    cout << "Policy2 Compact: " << policy2->toCompactString() << endl;
    return true;
  } else {
    cerr << "Error occurred during parsing." << endl;
  }
  return false;
}

bool TestAttributeList(const char *str) {
  try {
    std::unique_ptr<OpenABEAttributeList> attrList = createAttributeList(str);
    if (attrList != nullptr) {
      cout << "AttrList Full: " << attrList->toString() << endl;
      cout << "AttrList Compact: " << attrList->toCompactString() << endl;
      std::unique_ptr<OpenABEAttributeList> attrList2 = nullptr;
      attrList2.reset(attrList->clone());

      cout << "AttrList2 Full: " << attrList2->toString() << endl;
      cout << "AttrList2 Compact: " << attrList2->toCompactString() << endl;
      const vector<string> *raw_attrs = attrList->getAttributeList();
      cout << "Number of raw attributes: " << raw_attrs->size() << endl;
      return true;
    }
  } catch(OpenABE_ERROR & error) {
      cerr << "Error: " << OpenABE_errorToString(error) << endl;
  }
  return false;
}

bool TestCheckSatisfy(const string& policy_str, const string& attributes, bool verbose) {
  pair<bool,int> result;
  try {
    std::unique_ptr<OpenABEPolicy> policy = createPolicyTree(policy_str);
    std::unique_ptr<OpenABEAttributeList> attrList = createAttributeList(attributes);
    if (policy != nullptr && attrList != nullptr) {
      if (verbose) {
        cout << "Policy: " << policy->toString() << endl;
        cout << "Policy Compact: " << policy->toCompactString() << endl;
        cout << endl;
        cout << "AttrList: " << attrList->toString() << endl;
        cout << "AttrList Compact: " << attrList->toCompactString() << endl;
        cout << endl;
      }
      result = checkIfSatisfied(policy.get(), attrList.get());
      cout << "Check if satisfied => " << (result.first ? "true" : "false") << endl;
      cout << "Number of matches => " << result.second << endl;
      return result.first;
    } else {
      throw OpenABE_ERROR_INVALID_INPUT;
    }
  } catch(OpenABE_ERROR& error) {
    cout << "Error: " << OpenABE_errorToString(error) << endl;
  }
  return false;
}

int main(int argc, char **argv)
{
    bool verbose = false;
    if(argc < 3) {
      cout << "Usage " << string(argv[0]) << ": [ policy, attributes or logic ] [ input args ] [ verbose ]" << endl;
      exit(-1);
    }
    const string cmd(argv[1]);

    if (cmd == "policy") {
       return (TestPolicy(argv[2]) ? 0 : 1);
    } else if(cmd == "attributes") {
       return (TestAttributeList(argv[2]) ? 0 : 1);
    } else if(cmd == "logic") {
      if (argc == 5) {
        const string verb = argv[4];
        if (verb == "true") {
            verbose = true;
        }
      } else if (argc < 4) {
        cout << "expecting a 'policy' and an 'attribute list'" << endl;
        return -1;
      }
      const string policy_str = argv[2];
      const string attr_list = argv[3];
      return (TestCheckSatisfy(policy_str, attr_list, verbose) ? 0 : 1);
    } else {
      cout << "Command Options: 'policy', 'attributes' or 'logic' " << endl;
      exit(-1);
    }

  return -1;
}
