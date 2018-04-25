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
/// \file   fuzz_policy.cpp
///
/// \brief  This isolates policy parsing for fuzzing
///         using afl-fuzz and similar tools.
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>

#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

void getFile(std::string &result, const std::string &filename) {
  result.clear();

  fstream fs(filename, fstream::in);
  if (fs.fail()) {
    string msg = "Could not open file ";
    msg += filename;
    throw ios_base::failure(msg);
  }

  fs.exceptions(fstream::badbit);
  while (!fs.eof()) {
    char buf[512];
    fs.read(buf, sizeof(buf));
    result.append(buf, fs.gcount());
  }

  fs.close();
}

size_t getFileLen(const std::string &filename) {
  FILE *f = fopen(filename.c_str(), "r");
  if (!f) {
    string msg("Could not open file: ");
    msg += filename;
    throw ios_base::failure(msg);
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    throw ios_base::failure("fseek failed");
  }
  ssize_t result = ftell(f);
  if (result < 0) {
    throw ios_base::failure("ftell failed");
  }
  if ((uint64_t)result > SIZE_MAX) {
    throw ios_base::failure("file is too large");
  }
  return (size_t)result;
}

void putFile(const std::string &contents, const std::string &filename) {
  fstream fs(filename, fstream::out | fstream::trunc);

  if (fs.fail()) {
    string msg("Could not open file ");
    msg += filename;
    throw ios_base::failure(msg);
  }
  fs.exceptions(fstream::badbit | fstream::failbit);

  fs << contents;
  fs.close();
}


int main(int argc, char **argv) {
  // check that we have appropriate # of args
  if (argc < 2) {
    cerr << "Usage " << argv[0] << ": [ input file ]" << endl;
    return 1;
  }
  const string input_file(argv[1]);
  int err_code = 1;

  try {
    string policy_str;
    getFile(policy_str, input_file);
    vector<string> policy_strings = oabe::split(policy_str, '\n');

    for (auto p : policy_strings) {
      cout << "Input: " << p << endl;
      std::unique_ptr<OpenABEPolicy> policy = createPolicyTree(p);
      if(policy != nullptr) {
        cout << "Policy Full: " << policy->toString() << endl;
        cout << "Policy Compact: " << policy->toCompactString() << endl;
      } else {
        cerr << "Policy is NULL!" << endl;
      }
      cout << endl;
    }
    err_code = 0;
  } catch (const std::ios_base::failure& e) {
    // invalid input file specified
    cerr << e.what() << endl;
  }

  return err_code;
}
