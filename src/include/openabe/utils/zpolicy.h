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
/// \file   zpolicy.h
///
/// \brief  Class definition for OpenABE policy which is a subclass
///         of OpenABEFunctionInput (represents ABE policies).
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZPOLICY_H__
#define __ZPOLICY_H__

#include <iostream>
#include <memory>
#include <sstream>
#include <map>

#include "openabe/zobject.h"
#include "openabe/utils/zfunctioninput.h"

namespace oabe {

// forward declare
class OpenABEByteString;
#define PREFIX_SEP  ':'

typedef enum _zGateType {
  GATE_TYPE_NONE = 0,
  GATE_TYPE_LEAF,
  GATE_TYPE_AND,
  GATE_TYPE_OR,
  GATE_TYPE_THRESHOLD,
  GATE_TYPE_XOR,
  GATE_TYPE_NOT,
  GATE_TYPE_NAND,
  GATE_TYPE_NOR,
  GATE_TYPE_XNOR
} zGateType;

///
/// @class  OpenABETreeNode
///
/// @brief  Helper class that describes a single node in a policy tree.
///

class OpenABETreeNode : public ZObject {
protected:
  zGateType                   m_nodeType;
  uint32_t                    m_thresholdValue;
  uint32_t                    m_numSubnodes;
  bool                        m_Mark;
  int                         m_Satisfied;
  std::vector<OpenABETreeNode*>   m_Subnodes;
  std::string                 m_Prefix;
  std::string                 m_Label;
  int                         m_Index;
    
public:
  // Constructors/destructors
  OpenABETreeNode();
  OpenABETreeNode(std::string label, std::string prefix = "", int index = 0);
  OpenABETreeNode(OpenABETreeNode *copy);
  ~OpenABETreeNode();
  bool m_Visited;
    
  uint32_t getNumSubnodes()  { return this->m_Subnodes.size(); }
  const bool getMark() const { return this->m_Mark; }
  const int getNumSatisfied() const { return this->m_Satisfied; }
  bool setMark(bool mark, int satisfied)  {
    this->m_Mark = mark;
    this->m_Satisfied = satisfied;
    return mark;
  }
  const uint32_t  getNodeType() const { return this->m_nodeType; }
  void  setNodeType(zGateType type) { this->m_nodeType = type; }
  OpenABETreeNode*  getSubnode(uint32_t index);

  void addSubnode(OpenABETreeNode* subnode);
  void setLabel(const std::string label) { this->m_Label = label; }
  const std::string& getPrefix() const  { return this->m_Prefix; }
  const std::string& getLabel() const	{ return this->m_Label; }
  const std::string getCompleteLabel() const {
    if(this->m_Prefix != "") {
      std::string full_label(this->m_Prefix + PREFIX_SEP);
      full_label += this->m_Label;
      return full_label;
    } else {
      return this->m_Label;
    }
  }
  const int getIndex() const   { return this->m_Index; }
  void setThresholdValue(uint32_t k) { if (this->m_Subnodes.size() > 0) { this->m_thresholdValue = k; } }
  uint32_t getThresholdValue();
  std::string toString();
};

///
/// @class  OpenABEPolicy
///
/// @brief  Subclass of OpenABEFunctionInput that represents ABE policies.
///

class OpenABEPolicy : public OpenABEFunctionInput {
protected:
  std::unique_ptr<OpenABETreeNode> m_rootNode;
  bool m_hasDuplicates, m_enabledRevocation;
  std::map<std::string, int> m_attrDuplicateCount;
  std::set<std::string> m_attrCompleteSet;
  std::string m_originalInputString;

public:
  // Constructors/destructors
  OpenABEPolicy();
  OpenABEPolicy(const OpenABEPolicy &copy);
  virtual ~OpenABEPolicy();

  void setRootNode(OpenABETreeNode* subtree);
  OpenABETreeNode *getRootNode() const { return this->m_rootNode.get(); }
  OpenABEPolicy*    clone() const { return new OpenABEPolicy(*this); }
  void serialize(OpenABEByteString &result) const;
  bool isEqual(ZObject* z) const {
    return false;
  }
  OpenABEPolicy&    operator=(const OpenABEPolicy &rhs);
  std::string  toString() const {
      return this->m_rootNode->toString();
  }
  void setCompactString(const std::string& input) {
      m_originalInputString = input;
  }
  std::string toCompactString() const {
      return m_originalInputString;
  }

  // methods for storing/retrieving duplicate node info
  bool hasDuplicateNodes() const { return this->m_hasDuplicates; }
  void setDuplicateInfo(std::map<std::string, int>& attr_count, std::set<std::string>& attr_list);
  void setPrefixSet(std::set<std::string>& prefix_set);
  void getDuplicateInfo(std::map<std::string, int>& attr_count) const {
      attr_count = this->m_attrDuplicateCount;
  }
  bool getRevocationStatus() { return this->m_enabledRevocation; }
  void enableRevocation() { this->m_enabledRevocation = true; }

  std::set<std::string>& getAttrCompleteSet() {
    return this->m_attrCompleteSet;
  }

#if 0
  void		ConstructTestPolicy();
#endif
  friend std::ostream& operator<<(std::ostream& s, const OpenABEPolicy& z) {
    s << z.getRootNode()->toString();
    return s;
  }

  void deserialize(const OpenABEByteString &input);
};

// split a string based on a delimiter and return a vector
std::vector<std::string> split(const std::string &s, char delim);
// print the string of the internal tree node gate
const char* OpenABETreeNode_ToString(zGateType type);
std::unique_ptr<OpenABEPolicy> createPolicyTree(std::string s);
// reset all the flags in a policy tree
bool resetFlags(OpenABETreeNode *root);
// use to add an attribute at the OpenABEPolicy structure
std::unique_ptr<OpenABEPolicy> addToRootOfInput(
            zGateType type,
            const std::string attribute, OpenABEPolicy* policy);
}

#endif /* ifdef  __ZPOLICY_H__ */
