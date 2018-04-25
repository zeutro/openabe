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


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/zsymcrypto.h>

using namespace std;
using namespace oabe;

int main(int argc, char **argv) {
  string the_key, derived_key, key_data, ciphertext, plaintext1, plaintext2;

  string the_key_str, derived_key_str;
  cout << "Generate random key..." << endl;
  crypto::generateSymmetricKey(the_key, 32);
  the_key_str = crypto::printAsHex(the_key);
  cout << "Key: " << the_key_str << endl;

  std::unique_ptr<crypto::OpenABESymKeyHandle> keyHandle(new crypto::OpenABESymKeyHandleImpl(the_key));
  keyHandle->exportKey(derived_key);
  derived_key_str = crypto::printAsHex(derived_key);
  cout << "Derived Key: " << derived_key_str << endl;

  // assert that key and derived key are not equal
  if (the_key_str.compare(derived_key_str) != 0) {
    cout << "Exported a different key!" << endl;
  }

  // test encryption
  plaintext1 = "this is plaintext!";
  keyHandle->encrypt(ciphertext, plaintext1);

  cout << "Ciphertext: " << crypto::printAsHex(ciphertext) << endl;

  // test decryption
  keyHandle->decrypt(plaintext2, ciphertext);

  if (plaintext1 != plaintext2) {
      cout << "Decryption failed!!" << endl;
      return 1;
  }

  cout << "Successful Decryption!" << endl;
  return 0;
}
