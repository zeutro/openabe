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
/// \file   zpolicy.cpp
///
/// \brief  Implementation for OpenABE policy
///
/// \author Matthew Green and J. Ayo Akinyele
///

#define __OpenABEPOLICY_CPP__

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <openabe/openabe.h>

using namespace std;

/********************************************************************************
 * Implementation of the OpenABEPolicy class
 ********************************************************************************/
namespace oabe {

/*!
 * Constructor for the OpenABEPolicy class.
 *
 */

OpenABEPolicy::OpenABEPolicy() : OpenABEFunctionInput(),
        m_rootNode(nullptr), m_hasDuplicates(false), m_enabledRevocation(false) {
	this->m_Type = FUNC_POLICY_INPUT;
}

/*!
 * Copy constructor for the OpenABEPolicy class.
 *
 */

OpenABEPolicy::OpenABEPolicy(const OpenABEPolicy &copy): OpenABEFunctionInput() {
  OpenABETreeNode *root = copy.getRootNode();

  // Copy the tree (routine can handle a NULL root)
  if (root != NULL) {
      this->m_rootNode = std::unique_ptr<OpenABETreeNode>(new OpenABETreeNode(root));
  } else {
      this->m_rootNode = nullptr;
  }
  this->m_hasDuplicates       = copy.m_hasDuplicates;
  this->m_enabledRevocation   = copy.m_enabledRevocation;
  this->m_attrDuplicateCount  = copy.m_attrDuplicateCount;
  this->m_attrCompleteSet     = copy.m_attrCompleteSet;
  this->m_prefixSet           = copy.m_prefixSet;
  this->m_Type                = copy.m_Type;
  this->m_originalInputString = copy.m_originalInputString;
}

/*!
 * Destructor for the OpenABEPolicy class.
 *
 */

OpenABEPolicy::~OpenABEPolicy() {
  this->m_rootNode.reset();
}


#if 0
void
OpenABEPolicy::ConstructTestPolicy() {
  if (this->m_rootNode == nullptr) {
        this->m_rootNode = std::unique_ptr<OpenABETreeNode>(new OpenABETreeNode());
  }

  OpenABETreeNode *left = new OpenABETreeNode("Alice");
  OpenABETreeNode *right = new OpenABETreeNode("Bob");
  OpenABETreeNode *right2 = new OpenABETreeNode("Charlie");

  this->m_rootNode->setNodeType(GATE_TYPE_AND);
  this->m_rootNode->addSubnode(left);
  this->m_rootNode->addSubnode(right);
  this->m_rootNode->addSubnode(right2);
}
#endif

void
OpenABEPolicy::setRootNode(OpenABETreeNode* subtree) {
  this->m_rootNode = std::unique_ptr<OpenABETreeNode>(subtree);
}

void
OpenABEPolicy::serialize(OpenABEByteString &result) const {  }

std::unique_ptr<OpenABEPolicy> createPolicyTree(std::string s) {
  oabe::Driver driver(false);
  if(s.size() == 0) {
      return nullptr;
  }
  /* construct policy now */
  try {
    driver.parse_string(POLICY_PREFIX, s);
    return driver.getPolicy();
  } catch(OpenABE_ERROR & error) {
    cerr << "OpenABE Error: " << OpenABE_errorToString(error) << endl;
    return nullptr;
  }
}

unique_ptr<OpenABEPolicy>
addToRootOfInput(zGateType type, const string attribute, OpenABEPolicy* policy) {
  ASSERT_NOTNULL(policy);
  if(!policy->getRevocationStatus()) {
      // add attribute to policy
      string new_pol = "(";
      new_pol += policy->toCompactString() + ")";
      new_pol += OpenABETreeNode_ToString(type) + attribute;
      return createPolicyTree(new_pol);
  } else {
      // revocation is enabled so must search for the appropriate
      // attribute and extend
      throw OpenABE_ERROR_NOT_IMPLEMENTED;
  }
  return nullptr;
}


OpenABEPolicy&
OpenABEPolicy::operator=(OpenABEPolicy const &rhs) {
  // Protect against self-assignment
  if (this != &rhs) {
    // Free the pairing structure associated with the current
    // object, and move the new one in
    this->m_rootNode.reset();
    // set this rootNode to the rhs and perform copy via OpenABETreeNode class
    this->m_rootNode = std::unique_ptr<OpenABETreeNode>(new OpenABETreeNode(rhs.getRootNode()));
  }

  return *this;
}

void
OpenABEPolicy::setDuplicateInfo(std::map<std::string, int>& attr_count, std::set<std::string>& attr_list) {
	if(attr_list.size() > 0) {
    this->m_hasDuplicates = true;
    // set<string>::iterator it;
    for(auto it = attr_list.begin(); it != attr_list.end(); ++it) {
      // copy over data for the duplicate attributes only (ignore everything else)
      this->m_attrDuplicateCount[ *it ] = attr_count[ *it ];
      // cout << "Duplicate: " << *it << " => " << this->m_attrDuplicateCount[*it] << endl;
    }
	}

  // record the list of attributes (for easy access)
  for (auto& it : attr_count) {
    // cout << "ATTR: " << it.first << endl;
    this->m_attrCompleteSet.insert(it.first);
  }
}

void
OpenABEPolicy::setPrefixSet(set<string>& prefix_set) {
  m_prefixSet = prefix_set;
}

/********************************************************************************
 * Implementation of the OpenABETreeNode class
 ********************************************************************************/

/*!
 * Constructor.
 *
 */

OpenABETreeNode::OpenABETreeNode() : m_nodeType(GATE_TYPE_NONE), m_thresholdValue(0),
                             m_numSubnodes(0), m_Mark(false), m_Prefix(""),
                             m_Label(""), m_Index(0), m_Visited(false) {
}

/*!
 * Constructor for leaf nodes
 *
 */

OpenABETreeNode::OpenABETreeNode(string label, string prefix, int index) :
                         m_nodeType(GATE_TYPE_LEAF), m_thresholdValue(0),
                         m_numSubnodes(0), m_Mark(false), m_Prefix(prefix),
                         m_Label(label), m_Index(index), m_Visited(false) {
}

/*!
 * Get the threshold value, which is computed based on the gate type.
 *
 * @return - the threshold value of this gate as an int
 * @throw  - an exception if there is a problem sharing the element
 */

uint32_t
OpenABETreeNode::getThresholdValue() {
  uint32_t result = 0;

  // Handle each case
  switch(this->m_nodeType) {
    case GATE_TYPE_AND:
        result = this->getNumSubnodes();
        break;
    case GATE_TYPE_OR:
        result = 1;
        break;
    case GATE_TYPE_THRESHOLD:
        result = this->m_thresholdValue;
        break;
    default:
        OpenABE_LOG_AND_THROW("Illegal gate type", OpenABE_ERROR_INVALID_POLICY);
        break;
  }

  return result;
}

/*!
 * Get the subnode at position "index".
 *
 * @param				   - the parameter to return
 * @return                 - the subnode
 * @throw                  - an exception if the subnode doesn't exist
 */

OpenABETreeNode*
OpenABETreeNode::getSubnode(uint32_t index) {
  if (index >= this->getNumSubnodes()) {
    OpenABE_LOG_AND_THROW("Invalid policy subnode requested", OpenABE_ERROR_INVALID_INPUT);
  }

  return this->m_Subnodes[index];
}

/*!
 * Copy constructor. Recursively copy the given subtree.
 *
 * @throw            - an exception if there is a problem copying the policy
 */

OpenABETreeNode::OpenABETreeNode(OpenABETreeNode *copy) {
  if (copy == NULL) {
      OpenABE_LOG_AND_THROW("Copy with NULL pointer", OpenABE_ERROR_UNKNOWN);
  }

  this->m_nodeType            = copy->m_nodeType;
  if(this->m_nodeType == GATE_TYPE_LEAF) {
    this->m_Prefix          = copy->m_Prefix;
    this->m_Label           = copy->m_Label;
    return;
  }

  this->m_thresholdValue      = copy->m_thresholdValue;
  this->m_numSubnodes         = copy->m_numSubnodes;
  // reset state in copied object (we want to copy nodes only)
  this->m_Mark                = false;
  this->m_Visited             = false;
  this->m_Index               = copy->m_Index;
  // Now copy the subnodes vector. This is a vector of pointers
  // so we need to actually allocate memory and copy.

  // First, copy the vector itself.
  this->m_Subnodes            = copy->m_Subnodes;

  // Now instantiate a new OpenABETreeNode for each pointer in the vector.
  // This will recursively call (this) copy constructor for all
  // subnodes.
  for (uint32_t i = 0; i < this->m_Subnodes.size(); i++) {
      this->m_Subnodes[i] = new OpenABETreeNode(copy->m_Subnodes[i]);
      // reset state in copied object (we want to copy nodes only)
      this->m_Subnodes[i]->m_Mark    = false;
      this->m_Subnodes[i]->m_Visited = false;
  }
}


/*!
 * Convert a given subtree to a string.
 *
 */
string
OpenABETreeNode::toString() {
  string op = "";
  string tree = "";
  stringstream tmp;
  /* Initialize threshold to 0 to avoid false positive gcc
  variable uninitialized warning */
  int threshold = 0;
  bool recurse = false;
  if(this->m_nodeType == GATE_TYPE_LEAF) {
    if(this->m_Prefix != "") {
      const string thePrefix = this->m_Prefix + COLON;
      return thePrefix + this->m_Label;
    }
    return this->m_Label;
  }

  switch(this->m_nodeType) {
    case GATE_TYPE_AND:
        op = " and ";
        threshold = this->m_Subnodes.size();
        recurse = true;
        break;
    case GATE_TYPE_OR:
        op = " or ";
        threshold = 1;
        recurse = true;
        break;
    case GATE_TYPE_THRESHOLD:
        tmp << this->m_thresholdValue << " of ";
        op = tmp.str();
        break;
    default:
        OpenABE_LOG_AND_THROW("Illegal gate type", OpenABE_ERROR_INVALID_POLICY);
        break;
  }

  if(this->m_Subnodes.size() == 2) {
    tree += "(";
    if(recurse) {
      tree += this->m_Subnodes[0]->toString() + op + this->m_Subnodes[1]->toString();
    }
    tree += ")";
  }
  else {
    if(this->m_nodeType == GATE_TYPE_AND || this->m_nodeType == GATE_TYPE_OR) {
      tmp << threshold << " of ";
      tree = tmp.str();
    }
    tree += "(";
    for (uint32_t i = 0; i < this->m_Subnodes.size(); i++) {
      tree += this->m_Subnodes[i]->toString() + ", ";
    }
    tree.erase(tree.size()-2, tree.size());
    tree += ")";
  }

  return tree;
}

/*
 * Iterative pre-order traversal to set each m_Mark and m_Visited flags to false
 */
bool resetFlags(OpenABETreeNode *root) {
  std::stack<OpenABETreeNode*> stack;
  OpenABETreeNode *top = nullptr;
  if(root == nullptr)
    return false;
  stack.push(root);

  while(!stack.empty()) {
    // visit the top element on the stack, then pop it
    top = stack.top();
    // reset flags here top and move on
    top->setMark(false, 0);
    top->m_Visited = false;
    // pop element
    stack.pop();

    if(top->getNodeType() != GATE_TYPE_LEAF) {
        // visit children of node and push them on the stack
        for(size_t i = 0; i < top->getNumSubnodes(); i++) {
            stack.push(top->getSubnode(i));
        }
    }
  }

  return true;
}

/*!
 * Destructor. Dereference any memory used by this structure.
 *
 * @throw        - an exception if there is a problem 
 */

OpenABETreeNode::~OpenABETreeNode() {
  // Go through each subnode.
  for (uint32_t i = 0; i < this->m_Subnodes.size(); i++) {
    if (this->m_Subnodes[i] != NULL) {
        uint32_t count = this->m_Subnodes[i]->getRefCount();
        for (uint32_t j = 0; j < count; j++)
          this->m_Subnodes[i]->deRef();
    }
  }
}

void
OpenABETreeNode::addSubnode(OpenABETreeNode *subnode) {
  this->m_Subnodes.push_back(subnode);
  this->m_numSubnodes++;
}

const char*
OpenABETreeNode_ToString(zGateType type) {
  switch(type) {
    case GATE_TYPE_OR:
      return " or ";
      break;
    case GATE_TYPE_AND:
      return " and ";
      break;
    case GATE_TYPE_THRESHOLD:
      return " of ";
      break;
    default:
      break;
  }

  return "";
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
      if(!item.empty()) {
          elems.push_back(item);
      }
  }
  return elems;
}

std::vector<std::string> split(const std::string &s, char delim) {
  std::vector<std::string> elems;
  split(s, delim, elems);
  return elems;
}

}
