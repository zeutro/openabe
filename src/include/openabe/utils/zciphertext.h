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
///	\file   zciphertext.h
///
///	\brief  Class definition files for a functional encryption ciphertext.
///         This may be subclassed for specific FE schemes.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZCIPHERTEXT_H__
#define __ZCIPHERTEXT_H__

#include <map>

/// \class	ZCiphertext
/// \brief	Generic container for Functional Encryption ciphertexts.
///         May be subclassed for specific schemes.
namespace oabe {

class OpenABECiphertext : public OpenABEContainer {
protected:
	// 32-bytes for representing OpenABECiphertext Header information as follows:
	// 1 bytes for the library version
	uint8_t libraryVersion;
	// 1 byte for the curve identifier
	uint8_t curveID;
	// 1 byte for algorithm/scheme ID
	uint8_t algorithmID;
	// 32 bytes for UID
	OpenABEByteString uid;
	// whether the uid has been set externally
	// default is false
	bool uid_set_extern;

public:
  OpenABECiphertext();
  OpenABECiphertext(std::shared_ptr<ZGroup> group);
  OpenABECiphertext(const OpenABEByteString& uid);
  ~OpenABECiphertext();

  void setHeader(OpenABECurveID curveID, OpenABE_SCHEME scheme_type, OpenABERNG *rng);
  void setHeader(OpenABECurveID curveID, OpenABE_SCHEME scheme_type, OpenABEByteString &uid);
  void getHeader(OpenABEByteString &header);

  void setSchemeType(OpenABE_SCHEME scheme_type) { this->algorithmID    = scheme_type; }
  OpenABE_SCHEME getSchemeType() { return (OpenABE_SCHEME) this->algorithmID; }
  uint8_t getCurveID() { return this->curveID; }
  uint8_t getAlgorithmID() { return this->algorithmID; }
  uint8_t getLibID() { return this->libraryVersion; }
  OpenABEByteString& getUID() { return this->uid; }

  // export and import methods for ciphertext components
  // this includes the OpenABE header and the contents of the ciphertext
  void exportToBytes(OpenABEByteString &output);
  void loadFromBytes(OpenABEByteString &input);

  void exportToBytesWithoutHeader(OpenABEByteString& output);
  void loadFromBytesWithoutHeader(OpenABEByteString& input);
};

}

#endif	// __ZCIPHERTEXT_H__
