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
/// \file   zlsss.h
///
/// \brief  Class definition files for a secret sharing context.
///         Includes all routines necessary for secret sharing in the OpenABE.
///
/// \author Matthew Green and J. Ayo Akinyele
///

#ifndef __ZLSSS_H__
#define __ZLSSS_H__

#include <stack>
#include <vector>

namespace oabe {

/// \class  ZLSSSElement
/// \brief  Individual element of a secret sharing structure.
class OpenABELSSSElement : public ZObject {
protected:
  std::string m_Prefix, m_Label;
  ZP m_Element;
    
public:
  OpenABELSSSElement() { }
  OpenABELSSSElement(std::string label, ZP &element);
  OpenABELSSSElement(const OpenABELSSSElement &copy)
     : m_Prefix(copy.prefix()), m_Label(copy.label()), m_Element(copy.element()) { }
    
  // Public methods
  std::string label() const   { return this->m_Label; }
  std::string prefix() const { return this->m_Prefix; }
  ZP  element() const       { return this->m_Element; }
    
  // This method allows you to use the STL count() method to count the
  // number of entries that match a given label. Note that it only
  // compares to m_Label.
  bool operator==(const std::string &label) { return (label == this->m_Label); }
  friend std::ostream& operator<<(std::ostream& s, const OpenABELSSSElement& z) {
    OpenABELSSSElement z2(z);
    // note that label includes the prefix implicitly
    s << z2.m_Label << " -> " << z2.m_Element << "\n";
    return s;
  }
};

/// \typedef    OpenABELSSSRowMap
/// \brief      Key/value map of results in an LSSS
typedef std::map<const std::string, OpenABELSSSElement> OpenABELSSSRowMap;

/// \typedef    OpenABELSSSRowMapIterator
/// \brief      Iterator for vector of results in an LSSS
typedef OpenABELSSSRowMap::iterator OpenABELSSSRowMapIterator;

/// \class	ZLSSS
/// \brief	Secret sharing class.

class OpenABELSSS : public ZObject {
protected:
  OpenABEPairing *m_Pairing;
  OpenABERNG *m_RNG;
  OpenABELSSSRowMap	m_ResultMap;
  bool debug;
  ZP zero, iPlusOne, indexPlusOne;
  std::map<std::string, int> m_AttrCount;

  // Protected methods
  void performSecretSharing(const OpenABEPolicy *policy, ZP &elt);
  bool performCoefficientRecovery(OpenABEPolicy *policy, OpenABEAttributeList *attrList);

  void addShareToResults(OpenABETreeNode *treeNode, ZP &elt);
  bool clearExistingResults() { this->m_ResultMap.clear(); return true; }
  inline std::string makeUniqueLabel(const OpenABETreeNode *treeNode);
  inline ZP evaluatePolynomial(std::vector<ZP> &coefficients, uint32_t x);

  void iterativeShareSecret(OpenABETreeNode *treeNode, ZP &elt);
  bool iterativeCoefficientRecover(OpenABETreeNode *treeNode, ZP &inCoeff);
  inline ZP calculateCoefficient(OpenABETreeNode *treeNode, uint32_t index, uint32_t threshold, uint32_t total);

public:
  OpenABELSSS(OpenABEPairing *pairing, OpenABERNG *rng);
  ~OpenABELSSS();
    
  // Public secret sharing and recovery methods
  void shareSecret(const OpenABEFunctionInput *input, ZP &elt);
  bool recoverCoefficients(OpenABEPolicy *policy, OpenABEAttributeList *attrList);

  // Methods for obtaining the rows
  OpenABELSSSRowMap&            getRows() { return m_ResultMap; }
	
#ifndef OpenABE_NO_TEST_ROUTINES
	//
	// Test routine we use to make sure secret sharing is working
	//
	ZP LSSStestSecretRecovery(const OpenABELSSSRowMap& coefficients, const OpenABELSSSRowMap& shares);
#endif // OpenABE_NO_TEST_ROUTINES
};

bool iterativeScanTree(OpenABETreeNode *treeNode, OpenABEAttributeList *attributeList);
bool determineIfNodeShouldBeMarked(uint32_t threshold, OpenABETreeNode *node);
std::pair<bool,int> checkIfSatisfied(OpenABEPolicy *policy, OpenABEAttributeList *attr_list, bool reset_flags=true);

}

#endif	// __ZLSSS_H__
