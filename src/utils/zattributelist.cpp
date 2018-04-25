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
/// \file   ZAttributeList.cpp
///
/// \brief  Class implementation for storing attribute lists.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OpenABEATTRIBUTELIST_CPP__

#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEAttributeList class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the ZAttributeList class.
 *
 */

OpenABEAttributeList::OpenABEAttributeList() : OpenABEFunctionInput() {
  this->m_Type = FUNC_ATTRLIST_INPUT;
}

/*!
 * Constructor for the ZAttributeList class.
 *
 */

OpenABEAttributeList::OpenABEAttributeList(uint32_t numArgs, std::vector<string> args)
    : OpenABEFunctionInput() {
  string c;
  if (numArgs != args.size())
    throw OpenABE_ERROR_INVALID_INPUT;

  for (size_t i = 0; i < args.size(); i++) {
    if (args[i] != "")
      this->addAttribute(args[i]);
  }

  this->m_Type = FUNC_ATTRLIST_INPUT;
}

OpenABEAttributeList::OpenABEAttributeList(const OpenABEAttributeList &copy) {
  this->m_Type = copy.getFunctionType();
  this->m_Attributes = copy.m_Attributes;
  this->m_OriginalAttributes = copy.m_OriginalAttributes;
  this->m_prefixSet = copy.m_prefixSet;
}

/*!
 * Destructor for the ZAttributeList class.
 *
 */

OpenABEAttributeList::~OpenABEAttributeList() { this->m_Attributes.clear(); }

/*!
 * Return a copy of the string list.
 *
 */

void OpenABEAttributeList::getStringList(std::vector<string> &attrStrings) {
  attrStrings = this->m_Attributes;
}

/*!
 * Sync orig attributes from attrList based on a prefix.
 *
 */

void OpenABEAttributeList::syncOrigAttributes(const string &prefix,
                                          OpenABEAttributeList &attrList) {
  for (auto &it : attrList.m_OriginalAttributes) {
    if (it.find(prefix) != string::npos) {
      this->m_OriginalAttributes.push_back(it);
    }
  }
}

/*!
 * Search for a string in the string list.
 *
 */

bool OpenABEAttributeList::matchAttribute(const string &attribute) {
  return (std::find(m_Attributes.begin(), m_Attributes.end(), attribute) !=
          m_Attributes.end());
}

bool OpenABEAttributeList::addAttribute(string attribute) {
  string c, str;
  // first extract prefix here (e.g., prefix:attribute)
  // before parsing the attribute itself
  if (attribute.find(COLON) != string::npos) {
    // attribute contains a ':'
    vector<string> list = split(attribute, COLON);
    if (list.size() > 1) {
      // first item in list is treated as
      this->m_prefixSet.insert(list[0]);
    }
  }

  // do a quick find for the '=' symbol: if not, then proceed as usual
  if (attribute.find(EQUALS) == string::npos) {
    this->m_Attributes.push_back(attribute);
  } else {
    // otherwise, parse as a numerical attribute (using regex)
    // NOTE: we already handled prefixes in first part so would be redundant here
    std::unique_ptr<OpenABEAttributeList> attr_list = oabe::createAttributeList(ATTR_SEP + attribute);
    const vector<string> *m_attrs = attr_list->getAttributeList();
    const vector<string> *orig_attrs = attr_list->getOriginalAttributeList();
    if (m_attrs && orig_attrs) {
      for (auto& a : *m_attrs)
        this->m_Attributes.push_back(a);
      for (auto& b : *orig_attrs)
        this->m_OriginalAttributes.push_back(b);
    }
  }

  return true;
}

void OpenABEAttributeList::setAttributes(vector<string> &attr_list,
                                     vector<string> &orig_attr_list,
                                     set<string> &prefix_list) {
  this->m_Attributes = attr_list;
  this->m_OriginalAttributes = orig_attr_list;
  this->m_prefixSet = prefix_list;
}

ostream &operator<<(ostream &os, const OpenABEAttributeList &attributeList) {
  int i = 0;
  OpenABEAttributeList attributeList2 = attributeList;
  for (std::vector<string>::iterator it = attributeList2.m_Attributes.begin();
       it != attributeList2.m_Attributes.end(); ++it) {
    os << i << ":" << *it << endl;
    i++;
  }
  return os;
}

std::string OpenABEAttributeList::toString() const {
  string s;
  s.push_back(ATTR_SEP);
  for (std::vector<std::string>::const_iterator it = this->m_Attributes.begin();
       it != this->m_Attributes.end(); ++it) {
    if (it->compare("") != 0) {
      s += *it;
      // add delimiter
      s.push_back(ATTR_SEP);
    }
  }
  return s;
}

std::string OpenABEAttributeList::toCompactString() const {
  string s;
  s.push_back(ATTR_SEP);
  for (auto &it : this->m_Attributes) {
    // if the attribute doesn't contain an expint, then proceed
    if (it.find(EXPINT) == string::npos) {
      s += it;
      s.push_back(ATTR_SEP);
    }
  }

  // add any original attributes to the end
  for (auto &it : this->m_OriginalAttributes) {
    s += it;
    s.push_back(ATTR_SEP);
  }
  return s;
}

void OpenABEAttributeList::serialize(OpenABEByteString &result) const {
  result = this->toCompactString();
}

void OpenABEAttributeList::deserialize(const OpenABEByteString &input) {}

bool OpenABEAttributeList::isEqual(ZObject *z) const {
  OpenABEAttributeList *z1 = dynamic_cast<OpenABEAttributeList *>(z);
  if (z1 != NULL) {
    vector<string> list(z1->m_Attributes.size() + this->m_Attributes.size());
    // order does not matter. verify the same attributes are present
    vector<string>::iterator iter = std::set_difference(
        z1->m_Attributes.begin(), z1->m_Attributes.end(),
        this->m_Attributes.begin(), this->m_Attributes.end(), list.begin());
    return iter->size() == 0; // > 0 means false
  }
  // return false;
  throw OpenABE_ERROR_INVALID_INPUT;
}

//bool OpenABEAttributeList::isNumeric(const string s) {
//  for (size_t i = 0; i < s.size(); i++) {
//    if (!isdigit(s[i])) {
//      return false;
//    }
//  }
//  return true;
//}

std::unique_ptr<OpenABEAttributeList> createAttributeList(const std::string &s) {
  oabe::Driver driver(false);
  if (s.size() == 0) {
    return nullptr;
  }
  /* construct attribute list */
  try {
    driver.parse_string(ATTRLIST_PREFIX, s);
    return driver.getAttributeList();
  } catch (OpenABE_ERROR &error) {
    cerr << "caught exception: " << OpenABE_errorToString(error) << endl;
    return nullptr;
  }
}
}
