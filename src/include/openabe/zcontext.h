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
///	\file   zcontext.h
///
///	\brief  Abstract base class for encryption scheme contexts.
///
///	\author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZCONTEXT_H__
#define __ZCONTEXT_H__

namespace oabe {

class OpenABEEllipticCurve;
class OpenABEPairing;
class OpenABEKeystore;

/// @class  OpenABEContext
///
/// @brief  Main context class for Zeutro toolkit. This class contains all state related
///         to a given scheme. Applications may initialize as many OpenABEContext instances
///         as they wish.
///

class OpenABEContext : public ZObject {
protected:
  std::unique_ptr<OpenABERNG>           m_RNG_;
  std::unique_ptr<OpenABEPairing>       m_Pairing_;
  std::unique_ptr<OpenABEEllipticCurve> m_EllipticCurve_;
  std::unique_ptr<OpenABEKeystore>      m_Keystore_;
  OpenABESecurityLevel                  m_SecurityLevel;
  OpenABE_SCHEME algID;
    
public:
  // Constructors/destructors
  OpenABEContext();
  virtual ~OpenABEContext();

  // Main functions
  OpenABEKeystore        *getKeystore() { return this->m_Keystore_.get(); }
  OpenABERNG				*getRNG() 	   { return this->m_RNG_.get(); }
  // extract higher-level group objects
  OpenABEPairing 			*getPairing()  { return this->m_Pairing_.get(); }
  OpenABEEllipticCurve	*getECCurve()  { return this->m_EllipticCurve_.get(); }

  OpenABE_SCHEME           getAlgorithmID() { return this->algID; }
  virtual OpenABE_ERROR	initializeCurve(const std::string groupParams) = 0;
  OpenABE_ERROR			loadUserSecretParams(const std::string &skID, const std::string &sk);
};

}

#endif	// __ZCONTEXT_H__
