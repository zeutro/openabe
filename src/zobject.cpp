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
/// \file       zobject.cpp
///
/// \brief      Implementation for the abstract OpenABE object.
///
/// \author     Matthew Green and J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Implementation of the ZObject class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the ZObject class.
 *
 */

ZObject::ZObject()
{
  this->refCount = 1;
}

/*!
 * Destructor for the ZObject class.
 *
 */

ZObject::~ZObject()
{
}

/*!
 * Increment the reference count.
 *
 */

void
ZObject::addRef()
{
    this->refCount++;
}

/*!
 * Decrement the reference count.
 *
 */

void
ZObject::deRef()
{
  if (this->refCount-- <= 0) {
      delete this;
  }
}

void
OpenABEZeroize(void *b, size_t b_len) {
  ASSERT_NOTNULL(b);
  volatile uint8_t *p = (uint8_t *)b;
  if (b_len > 0) {
    while( b_len-- ) {
        *p++ = 0;
    }
  }
}

/* helper methods to assist with serializing and base-64 encoding group elements */
static const string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

/* Note that the following was borrowed from Copyright (C) 2004-2008 Ren� Nyffenegger (*/

bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

string Base64Encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}

string Base64Decode(string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  size_t in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  // The only case where we have a valid input and the following
  // if happens is terminating '=' characters
  if (in_ < encoded_string.size()) {
    // Look for terminating '='s, maximum 2
    if (encoded_string.size() - in_ > 2) {
        throw OpenABE_ERROR_INVALID_INPUT;
    }
    size_t tmp = in_;
    for (; tmp < encoded_string.size(); tmp++) {
        if (encoded_string[tmp] != '=') {
            break;
        }
    }
    if (tmp != encoded_string.size()) {
        throw OpenABE_ERROR_INVALID_INPUT;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}

}
