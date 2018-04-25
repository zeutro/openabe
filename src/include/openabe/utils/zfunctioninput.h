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
/// \file   zfunctioninput.h
///
/// \brief  Abstract base class for various kinds of function inputs.
///         This generalize attribute lists, policies, etc.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZFUNCTIONINPUT_H__
#define __ZFUNCTIONINPUT_H__

#include <set>
#include <memory>

namespace oabe {

class OpenABECiphertext;
/// @typedef OpenABEFunctionInputType
///
/// @brief   Enumerates constant values corresponding to given function
///          input types, e.g., policies, attribute lists.

typedef enum _OpenABEFunctionInputType {
  FUNC_INVALID_INPUT = 0,
  FUNC_POLICY_INPUT = 1,
  FUNC_ATTRLIST_INPUT = 2
} OpenABEFunctionInputType;

///
/// @class  OpenABEFunctionInput
///
/// @brief  Abstract base class for inputs to the Functional Encryption
///         schemes. This includes such data types as policies, attribute
///         lists, strings and DFA descriptions (for RLE).
///

class OpenABEFunctionInput : public ZObject {
protected:
  OpenABEFunctionInputType   m_Type;
  std::set<std::string>  m_prefixSet;

public:
  // Constructors/destructors
  OpenABEFunctionInput();
  virtual ~OpenABEFunctionInput() = 0;
  bool includesPrefix(const std::string prefix) {
    std::set<std::string>::iterator it;
    it = m_prefixSet.find(prefix);
    // true if iterator ptr *not* at end of set
    // otherwise, false
    return (it != m_prefixSet.end());
  }

  const std::set<std::string>& getPrefixSet() { return this->m_prefixSet; }
  OpenABEFunctionInputType getFunctionType() const { return this->m_Type; }
  virtual std::string toString() const = 0;
  virtual std::string toCompactString() const = 0;
};

// perform deep copy of a function input
std::unique_ptr<OpenABEFunctionInput> copyFunctionInput(const OpenABEFunctionInput& input);
std::unique_ptr<OpenABEFunctionInput> getFunctionInput(OpenABECiphertext *ciphertext);

}

#endif /* ifdef  __ZFUNCTIONINPUT_H__ */
