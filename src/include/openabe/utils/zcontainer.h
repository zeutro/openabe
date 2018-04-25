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
///	\file   zcontainer.h
///
///	\brief  Class definition files for a generic container. Used
///         for keys and ciphertexts.
///
///	\author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZCONTAINER_H__
#define __ZCONTAINER_H__

#include <map>

namespace oabe {
class ZP;
class G;
}

/// \class	OpenABEContainer
/// \brief	Generic container for Functional Encryption data structures.
///         May be subclassed for specific schemes.
namespace oabe {

class OpenABEContainer : protected ZObject {
protected:
  std::shared_ptr<ZGroup> group;
  std::map<std::string, ZObject*> val;
  void deserialize(OpenABEByteString &blob);
  void deserialize(std::string &blob);
  void deserializeElement(std::string key, OpenABEByteString& value);
  void serialize(OpenABEByteString &result) const;
  // void serializeAsTuple(std::vector<std::string>& keys, OpenABEByteString &result) const;

public:
  OpenABEContainer();
  OpenABEContainer(std::shared_ptr<ZGroup> group);
  virtual ~OpenABEContainer();

  void        setGroup(std::shared_ptr<ZGroup> group) { this->group = group; }
  void        setComponent(const std::string &name, const ZObject *component);
  void        setComponent(const std::string &name, ZObject component);
  ZObject*    getComponent(const std::string &name);
  OpenABE_ERROR   deleteComponent(const std::string name);
  // Some helper methods for getting components of specific types
  ZP*	   getZP(const std::string &name) { return dynamic_cast<ZP*>(this->getComponent(name)); }
  G1*    getG1(const std::string &name) { return dynamic_cast<G1*>(this->getComponent(name)); }
  G2*    getG2(const std::string &name) { return dynamic_cast<G2*>(this->getComponent(name)); }
  GT*    getGT(const std::string &name) { return dynamic_cast<GT*>(this->getComponent(name)); }

  ZP_t*  getZP_t(const std::string &name) { return dynamic_cast<ZP_t*>(this->getComponent(name)); }
  G_t*   getG_t(const std::string &name) { return dynamic_cast<G_t*>(this->getComponent(name)); }

  OpenABEByteString* getByteString(const std::string &name) { return dynamic_cast<OpenABEByteString*>(this->getComponent(name)); }
  OpenABEUInteger* getInteger(const std::string &name) { return dynamic_cast<OpenABEUInteger*>(this->getComponent(name)); }
  uint32_t    numComponents();
  OpenABE_ERROR   zeroize();

  std::vector<std::string> getKeys();
  friend bool operator==(const OpenABEContainer&, const OpenABEContainer&);
};

inline std::string OpenABEMakeElementLabel(std::string base, std::string unique) { return base + "_" + unique; }

}
#endif	// __ZCONTAINER_H__
