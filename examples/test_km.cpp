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
/// \brief  Example use of the Keystore + OpenABE API with KP-ABE
///

#include <iostream>
#include <string>
#include <cassert>
#include <map>
#include <vector>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

int main(int argc, char **argv) {

  InitializeOpenABE();

  cout << "Testing KP-ABE context with Key Manager" << endl;

  OpenABECryptoContext kpabe("KP-ABE");

  string pt1 = "hello world!", pt2 = "another hello!", pt3 = "this should fail!";
  string rpt1, rpt2, rpt3, ct1, ct2, ct3;

  kpabe.generateParams();

  map<string,string> keyBlobs;
  string tmp;
  vector<string> key_inputs = { "(attr1 or attr2) and attr3", "attr1 and attr2", "attr2 and attr3", "attr3 and attr4" };
  // generate keys and delete from context (we will load later)
  for(size_t i = 0; i < key_inputs.size(); i++) {
    const string keyID = "key"+to_string(i+1);
    cout << "Generate " << keyID << ": " << key_inputs[i] << endl;
    kpabe.keygen(key_inputs[i], keyID);
    kpabe.exportUserKey(keyID, tmp);
    keyBlobs[ keyID ] = tmp;
    assert(kpabe.deleteKey(keyID));
  }

  // enable use of key manager
  kpabe.enableKeyManager("user1");
  kpabe.enableVerbose(); // more internal output to stdout

  map<string,string>::iterator it;
  // load the keystore with the generated keys
  for(it = keyBlobs.begin(); it != keyBlobs.end(); it++) {
      kpabe.importUserKey(it->first, it->second);
  }

  // encrypt
  kpabe.encrypt("|attr1|attr2", pt1, ct1);
  kpabe.encrypt("|attr3|attr4", pt2, ct2);
  kpabe.encrypt("|attr4|attr5", pt3, ct3);

  // decrypt
  bool result = kpabe.decrypt(ct1, rpt1);

  assert(result && pt1 == rpt1);
  cout << "Recovered message 1: " << rpt1 << endl;

  result = kpabe.decrypt(ct2, rpt2);
  assert(result && pt2 == rpt2);
  cout << "Recovered message 2: " << rpt2 << endl;

  try {
      result = kpabe.decrypt(ct3, rpt3);
  } catch (oabe::ZCryptoBoxException& ex) {
      cout << "Correctly failed to recover message 3!" << endl;
  }
  ShutdownOpenABE();

  return 0;
}
