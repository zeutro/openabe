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
///	\file   zbytestring.h
///
///	\brief  Generic class for handling byte strings. These strings can
///         include null (0) characters. Otherwise this class is
///         similar to a std::string.
///
///	\author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZBYTESTRING_H__
#define __ZBYTESTRING_H__

#include <cstring>
#include <vector>
#include <ostream>
#include <sstream>
#include <iostream>

#include "zcryptoutils.h"
#include "zconstants.h"

#define HEX_CHARS   "0123456789abcdefABCDEF"
#define BYTESTRING	0x1D
#define DEBUG_VAR(a,b) std::cerr << a << b << std::endl;

/// \class	OpenABEByteString
/// \brief	Generic container for manipulating a vector of bytes.
///         May be subclassed for specific schemes.
typedef enum PACK_TYPE {
  PACK_NONE = 0x00,
  PACK_8    = 0xA1,
  PACK_16   = 0xB2,
  PACK_32   = 0xC3,
  PACK_64   = 0xD4
} PackType;

namespace oabe {

class OpenABEByteString : public ZObject, public std::vector<uint8_t> {
	
public:
  OpenABEByteString& operator+=(const OpenABEByteString &concat) {
    this->insert(this->end(), concat.begin(), concat.end());
    return *this;
  }

  OpenABEByteString& operator+=(const std::string concat) {
    this->insert(this->end(), concat.begin(), concat.end());
    return *this;
  }

  OpenABEByteString& appendArray(uint8_t input[], uint32_t size) {
    this->insert(this->end(), &input[0], &input[size]);
    return *this;
  }

  OpenABEByteString operator+(OpenABEByteString &concat) {
    OpenABEByteString result;
    result.insert(result.end(), this->begin(), this->end());
    result.insert(result.end(), concat.begin(), concat.end());
    return result;
  }

  OpenABEByteString operator+(std::string concat) {
    OpenABEByteString result;
    uint32_t size = concat.size();
    result.insert(result.end(), this->begin(), this->end());
    result.insert(result.end(), ((uint8_t*) concat.c_str())[0], ((uint8_t*)concat.c_str())[size]);
    return result;
  }

  OpenABEByteString&    operator=(const std::string &rhs) {
    this->clear();
    this->insert(this->end(), rhs.begin(), rhs.end());
    return *this;
  }

  OpenABEByteString& operator^=(OpenABEByteString &rhs) {
    if (this->size() != rhs.size()) {
      THROW_ERROR(OpenABE_ERROR_INVALID_INPUT);
    } else {
      uint8_t *lhs_ptr = this->getInternalPtr();
      uint8_t *rhs_ptr = rhs.getInternalPtr();
      for(size_t i = 0; i < this->size(); i++) {
          lhs_ptr[i] = this->at(i) ^ rhs_ptr[i];
      }
      return *this;
    }
  }

  uint8_t *getInternalPtr() {
    return &((*this)[0]);
  }

  void zeroize() {
    size_t b_len = this->size();
    if (b_len > 0) {
        void *b = &((*this)[0]);
        OpenABEZeroize(b, b_len);
    }
    this->clear();
  }

  void eraseAll() {
    this->erase(this->begin(), this->end());
  }

  OpenABEByteString getSubset(size_t start_pos, size_t num_bytes) {
    OpenABEByteString result;
    uint8_t *ptr = this->getInternalPtr();
    if((start_pos + num_bytes) <= this->size()) {
        // copy the subset
        result.appendArray((uint8_t*) (ptr + start_pos), num_bytes);
    }
    return result;
  }

  void fillBuffer(uint8_t byte, uint32_t len) {
    // clear buffer
    this->clear();
    for(size_t i = 0; i < len; i++) {
      // fill with the given byte
      this->push_back(byte);
    }
  }

  void insertFirstByte(uint8_t byte) {
    this->insert(this->begin(), byte);
  }

  OpenABEByteString* clone() const {
    return new OpenABEByteString(*this);
  }

  std::string toHex() const {
    std::stringstream ss;
    int hex_len = 2;
    char hex[hex_len+1];
    std::memset(hex, 0, hex_len+1);

    for (std::vector<uint8_t>::const_iterator it = this->begin();
        it != this->end(); ++it) {
      sprintf(hex, "%02X", *it);
      ss << hex;
    }
    return ss.str();
  }

  std::string toLowerHex() const {
    std::stringstream ss;
    int hex_len = 2;
    char hex[hex_len+1];
    std::memset(hex, 0, hex_len+1);

    for (std::vector<uint8_t>::const_iterator it = this->begin() ; it != this->end(); ++it) {
        sprintf(hex, "%02x", *it);
        ss << hex;
    }
    return ss.str();
  }

  bool fromHex(std::string s) {
    if((s.find_first_not_of(HEX_CHARS) != std::string::npos) ||
            (s.size() % 2 != 0)) {
      return false;
    }

    std::string hex_str;
    std::stringstream ss;
    int tmp;

    this->clear();
    for (size_t i = 0; i < s.size(); i += 2) {
      hex_str  = s[i];
      hex_str += s[i+1];

      ss << hex_str;
      ss >> std::hex >> tmp;
      this->push_back(tmp & 0xFF);
      ss.clear();
    }

    return true;
  }

  void fromString(const std::string& concat) {
    this->clear();
    this->insert(this->end(), concat.begin(), concat.end());
  }

  const std::string toString() {
    std::stringstream ss;
    for (std::vector<uint8_t>::iterator it = this->begin() ; it != this->end(); ++it) {
      const unsigned char str = *it;
      ss << str;
    }
    return ss.str();
  }

  // constant time comparison for bytestring objects
  friend bool operator==(const OpenABEByteString& lhs, const OpenABEByteString& rhs) {
    if (lhs.size() != rhs.size())
      return false;
    int rc = 0;
    for (size_t i = 0; i < lhs.size(); i++) {
      rc |= (lhs.at(i) ^ rhs.at(i));
    }
    /* 0 => lhs == rhs, > 0 => lhs != rhs */
    return (rc == 0) ? true : false;
  }

  friend std::ostream& operator<<(std::ostream& s, const OpenABEByteString& z) {
    OpenABEByteString z2(z);
    for (std::vector<uint8_t>::iterator it = z2.begin() ; it != z2.end(); ++it) {
      s << *it;
    }
    return s;
  }

  void serialize(OpenABEByteString& result) const {
    result.clear();
    result.pack32bits((uint32_t) this->size());
    result.insertFirstByte(BYTESTRING);
    result += *this;
  }

  void deserialize(OpenABEByteString &input) {
    uint32_t len = 0;
    size_t hdrLen = 5;
    if (input.size() > hdrLen) {
      for (size_t i = 1; i <= sizeof(uint32_t); i++) {
        len <<= 8;
        len += input.at(i);
      }

      if(input.size() == (len + hdrLen)) {
        *this = input.getSubset(hdrLen, len);
      } else {
        THROW_ERROR(OpenABE_ERROR_DESERIALIZATION_FAILED);
      }
    } else {
      THROW_ERROR(OpenABE_ERROR_DESERIALIZATION_FAILED);
    }
  }

  bool isEqual(ZObject* z) const {
    OpenABEByteString *z1 = dynamic_cast<OpenABEByteString*>(z);
    if(z1 != NULL) {
      return *z1 == *this;
    }
    return false;
  }

  void pack8bits(uint8_t byte) {
    this->push_back(byte);
  }

  void pack16bits(uint16_t bytes) {
    uint8_t tmp_buf[sizeof(uint16_t)];
    tmp_buf[1] = (bytes & 0x00FF);
    tmp_buf[0] = (bytes & 0xFF00) >> 8;
    this->appendArray(tmp_buf, sizeof(uint16_t));
    return;
  }

  void pack32bits(uint32_t bytes) {
    uint8_t tmp_buf[sizeof(uint32_t)];
    uint32_t x = bytes;
    for (int i = sizeof(uint32_t); i > 0; i--) {
      tmp_buf[i-1] = (x & 0xFF);
      x >>= 8;
    }
    this->appendArray(tmp_buf, sizeof(uint32_t));
    return;
  }

  void setFirstBytes(uint32_t bytes) {
    uint8_t tmp_buf[sizeof(uint32_t)];
    uint32_t x = bytes;
    for (int i = sizeof(uint32_t); i > 0; i--) {
      tmp_buf[i-1] = (x & 0xFF);
      x >>= 8;
    }
    if(this->size() >= sizeof(uint32_t)) {
      (*this)[0] = tmp_buf[0];
      (*this)[1] = tmp_buf[1];
      (*this)[2] = tmp_buf[2];
      (*this)[3] = tmp_buf[3];
    } else {
      this->appendArray(tmp_buf, sizeof(uint32_t));
    }
  }

  void pack(uint8_t *buf, uint32_t buf_len) {
    this->pack32bits(buf_len);
    this->appendArray(buf, buf_len);
  }

  void pack(OpenABEByteString &buf) {
    uint32_t buf_size = buf.size();
    if(buf_size == 0) {
      THROW_ERROR(OpenABE_ERROR_INVALID_INPUT);
    }
    this->pack32bits(buf_size);
    this->appendArray(buf.getInternalPtr(), buf_size);
  }

  void smartPack(OpenABEByteString& buf) {
    // determine whether 8 or 16 or 32-bits are needed to pack the buffer
    // as a function of the entire size of the buffer
    if(buf.size() > UINT16_MAX) {
      // pack as 32-bit
      uint32_t buf_size = buf.size();
      this->push_back(PACK_32);
      this->pack32bits(buf_size);
    } else if(buf.size() > UINT8_MAX) {
      // all we need is 16-bits
      uint16_t buf_size = buf.size();
      this->push_back(PACK_16);
      this->pack16bits(buf_size);
    } else if (buf.size() > 0) {
      // all we need is 8-bits
      uint8_t buf_size = buf.size();
      this->push_back(PACK_8);
      this->pack8bits(buf_size);
    } else {
      THROW_ERROR(OpenABE_ERROR_INVALID_INPUT);
    }
    this->appendArray(buf.getInternalPtr(), buf.size());
    return;
  }

  OpenABEByteString smartUnpack(size_t *index) {
    size_t buf_len = this->size();
    if(*index + 1 > buf_len) {
      DEBUG_VAR("Index: ", *index);
      DEBUG_VAR("Buf Len: ", buf_len);
        THROW_ERROR(OpenABE_ERROR_INDEX_OUT_OF_BOUNDS);
    }

    PackType pack_type = (PackType) this->at(*index);
    *index += 1;
    if(pack_type == PACK_32) {
      return this->unpack(index);
    } else if(pack_type == PACK_16) {
      return this->unpack16bits(index);
    } else if(pack_type == PACK_8) {
      return this->unpack8bits(index);
    } else {
      std::cerr << "Pack type: " << pack_type << std::endl;
      THROW_ERROR(OpenABE_ERROR_INVALID_PACK_TYPE);
    }
    OpenABEByteString buf;
    return buf;
  }

  OpenABEByteString unpack8bits(size_t *index) {
    size_t index2 = *index;
    OpenABEByteString buf;
    size_t buf_len = this->size();
    if(index2 >= buf_len || (index2 + 1) > buf_len) {
      /* we've gone past the end of the buffer so stop */
      DEBUG_VAR("Index: ", index2);
      DEBUG_VAR("Buf Len: ", buf_len);
      THROW_ERROR(OpenABE_ERROR_INDEX_OUT_OF_BOUNDS);
    }
    uint16_t len = this->at(index2);
    // 1 byte for 8-bit type rep
    if(len > buf_len || (index2 + len + 1) > buf_len) {
      DEBUG_VAR("Len: ", len);
      DEBUG_VAR("Index: ", index2);
      DEBUG_VAR("Buf Len: ", buf_len);
      THROW_ERROR(OpenABE_ERROR_INDEX_OUT_OF_BOUNDS);
    }
    index2 += 1;

    for(size_t i = 0; i < len; i++) {
      buf.push_back(this->at(index2));
      index2++;
    }
    *index = index2;
    return buf;
  }

  OpenABEByteString unpack16bits(size_t *index) {
    size_t index2 = *index;
    OpenABEByteString buf;
    size_t buf_len = this->size();

    if (index2 >= buf_len || (index2 + 2) > buf_len) {
      DEBUG_VAR("Index: ", index2);
      DEBUG_VAR("Buf Len: ", buf_len);
      THROW_ERROR(OpenABE_ERROR_INDEX_OUT_OF_BOUNDS);
    }
    uint16_t len = 0;
    len |= this->at(index2+1);
    len |= (this->at(index2) << 8);

    // 2 byte for 16-bit type rep
    if(len > buf_len || (index2 + len + 2) > buf_len) {
      DEBUG_VAR("Len: ", len);
      DEBUG_VAR("Index: ", index2);
      DEBUG_VAR("Buf Len: ", buf_len);
      THROW_ERROR(OpenABE_ERROR_INDEX_OUT_OF_BOUNDS);
    }
    index2 += 2;
    for(size_t i = 0; i < len; i++) {
      buf.push_back(this->at(index2));
      index2++;
    }
    *index = index2;
    return buf;
  }

  OpenABEByteString unpack(size_t *index) {
    size_t index2 = *index;
    OpenABEByteString buf;
    size_t buf_len = this->size();

    if (index2 >= buf_len || (index2 + 4) > buf_len) {
      DEBUG_VAR("Index: ", index2);
      DEBUG_VAR("Buf Len: ", buf_len);
      THROW_ERROR(OpenABE_ERROR_INDEX_OUT_OF_BOUNDS);
    }
    uint32_t len = 0;
    len |= (this->at(index2) << 24);
    len |= (this->at(index2+1) << 16);
    len |= (this->at(index2+2) << 8);
    len |= this->at(index2+3);

    // 4 byte for 32-bit type rep
    if(len > buf_len || (index2 + len + 4) > buf_len) {
      DEBUG_VAR("Len: ", len);
      DEBUG_VAR("Index: ", index2);
      DEBUG_VAR("Buf Len: ", buf_len);
      THROW_ERROR(OpenABE_ERROR_INDEX_OUT_OF_BOUNDS);
    }
    index2 += 4;
    for (size_t i = 0; i < len; i++) {
      buf.push_back(this->at(index2));
      index2++;
    }
    *index = index2;
    return buf;
  }

  void unpack(size_t *index, OpenABEByteString & buf) {
    size_t index2 = *index;
    size_t buf_len = this->size();
    if (index2 >= buf_len || (index2 + 4) > buf_len) {
      THROW_ERROR(OpenABE_ERROR_INDEX_OUT_OF_BOUNDS);
    }
    uint32_t len = 0;
    len |= (this->at(index2) << 24);
    len |= (this->at(index2+1) << 16);
    len |= (this->at(index2+2) << 8);
    len |= this->at(index2+3);

    // 4 byte for 32-bit type rep
    if(len > buf_len || (index2 + len + 4) > buf_len) {
      THROW_ERROR(OpenABE_ERROR_INDEX_OUT_OF_BOUNDS);
    }
    index2 += 4;
    for (size_t i = 0; i < len; i++) {
      buf.push_back(this->at(index2));
      index2++;
    }
    *index = index2;
    return;
  }
};

}

#endif	// __ZBYTESTRING_H__
