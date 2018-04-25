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
/// \file   zcontextkpgpsw.h
///
/// \brief  Class definition for the KP-ABE [GPSW '06] scheme.
///
/// \source [GPSW 06, Sec 5] and [PTMW 06, Sec 2.2 + Appendix B]
///
/// \author J. Ayo Akinyele
///

#ifndef __ZCONTEXTKPGPSW_H__
#define __ZCONTEXTKPGPSW_H__

///
/// @class  OpenABEContextKPGPSW
///
/// @brief  Implementation of the GPSW '06 KP-ABE encryption scheme.
///
namespace oabe {

class OpenABEContextKPGPSW : public OpenABEContextABE {
public:
  // Constructors/destructors
  OpenABEContextKPGPSW(std::unique_ptr<OpenABERNG> rng);
  ~OpenABEContextKPGPSW();
  bool debug;

  // Main functions
  OpenABE_ERROR generateParams(OpenABESecurityLevel securityLevel,
                           const std::string &mpkID,
                           const std::string &mskID);

  OpenABE_ERROR generateParams(const std::string groupParams,
                           const std::string &mpkID,
                           const std::string &mskID);

  OpenABE_ERROR generateDecryptionKey(OpenABEFunctionInput *keyInput, const std::string &keyID,
                                  const std::string &mpkID, const std::string &mskID,
                                  const std::string &gpkID, const std::string &GID);

  OpenABE_ERROR encryptKEM(OpenABERNG *rng, const std::string &mpkID, const OpenABEFunctionInput *encryptInput,
                       uint32_t keyByteLen, const std::shared_ptr<OpenABESymKey>& key, OpenABECiphertext *ciphertext);

  OpenABE_ERROR decryptKEM(const std::string &mpkID, const std::string &keyID, OpenABECiphertext *ciphertext,
                       uint32_t keyByteLen, const std::shared_ptr<OpenABESymKey>& key);
};

}

#endif /* ifdef  __ZCONTEXTKPGPSW_H__ */
