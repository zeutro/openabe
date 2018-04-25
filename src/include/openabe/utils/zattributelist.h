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
/// \file   zattributelist.h
///
///	\brief  Subclass of OpenABEFunctionInput that represents ABE attribute lists.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZATTRIBUTELIST_H__
#define __ZATTRIBUTELIST_H__

#define EQUALS       '='
#define NUM_HASH     '#'
#define WHITESPACE   ' '
#define ATTR_SEP     '|'
namespace oabe {

///
/// @class  OpenABEAttributeList
///
/// @brief  Subclass of OpenABEFunctionInput that represents attributes.
///
class OpenABEAttributeList : public OpenABEFunctionInput {
protected:
  std::vector<std::string>     m_Attributes;
  std::vector<std::string>     m_OriginalAttributes;
  void setAttributes(std::vector<std::string>& attr_list,
                     std::vector<std::string>& orig_attr_list,
                     std::set<std::string>& prefix_list);

public:
  // Constructors/destructors
  OpenABEAttributeList();
  OpenABEAttributeList(const OpenABEAttributeList &copy);
  OpenABEAttributeList(uint32_t numArgs, std::vector<std::string> args);
  virtual ~OpenABEAttributeList();

  void getStringList(std::vector<std::string> &attrStrings);
  bool hasOrigAttributes() const { return (this->m_OriginalAttributes.size() > 0); }
  void syncOrigAttributes(const std::string& prefix, OpenABEAttributeList& attrList);
  bool matchAttribute(const std::string &attribute);
  bool addAttribute(std::string attribute);

  friend std::ostream& operator<<(std::ostream&, const OpenABEAttributeList&);
  const std::vector<std::string>*	 getAttributeList() const { return &this->m_Attributes; }
  const std::vector<std::string>*  getOriginalAttributeList() const { return &this->m_OriginalAttributes; }
  OpenABEAttributeList*    clone() const { return new OpenABEAttributeList(*this); }
  std::string toString() const;
  std::string toCompactString() const;
  void serialize(OpenABEByteString &result) const;
  void deserialize(const OpenABEByteString &input);
  bool isEqual(ZObject*) const;
  friend class Driver;

//private:
//  static bool isNumeric(const std::string s);
};

std::unique_ptr<OpenABEAttributeList> createAttributeList(const std::string& s);
}

#endif /* ifdef  __ZATTRIBUTELIST_H__ */
