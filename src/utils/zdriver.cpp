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
/// \file   zdriver.cpp
///
/// \brief  Driver implementation for parsing
///         and constructing OpenABE policy structures.
///
/// \author J. Ayo Akinyele
///

#include <fstream>
#include <sstream>
#include <iostream>
#include <bitset>
#include <math.h>
#include <time.h>

#include <openabe/utils/zdriver.h>
#include <openabe/utils/zscanner.h>

#ifndef __ZPOLICY_H__
#include <openabe/utils/zpolicy.h>
#endif

#ifndef __ZINTEGER_H__
#include <openabe/utils/zinteger.h>
#endif

#ifndef __ZATTRIBUTELIST_H__
#include <openabe/utils/zattributelist.h>
#endif

const size_t DAY_IN_SECS = 60*60*24;

using namespace std;

namespace oabe {

////////////////////// Driver for OpenABEPolicy //////////////////////

Driver::Driver(bool _debug) : trace_scanning(false), trace_parsing(false) {
  final_policy = nullptr;
  debug = _debug;
}

Driver::~Driver() {}

bool Driver::parse_stream(std::istream &in, const std::string &sname) {
  streamname = sname;

  Scanner scanner(&in);
  scanner.set_debug(trace_scanning);
  this->lexer = &scanner;

  Parser parser(*this);
  parser.set_debug_level(trace_parsing);
  return (parser.parse() == 0);
}

bool Driver::parse_string(const std::string &prefix, const std::string &input,
                          const std::string &sname) {
  std::istringstream iss(prefix + input);
  this->original_input = input;
  if (prefix == POLICY_PREFIX) {
    this->isPolicy = true;
  } else if (prefix == ATTRLIST_PREFIX) {
    this->isPolicy = false;
  } else {
    return false;
  }
  return parse_stream(iss, sname);
}

void Driver::error(const class location &l, const std::string &m) {
  std::cerr << "Driver::error " << l << ": " << m << std::endl;
  // clear state
  this->original_input = "";
  if (this->isPolicy) {
    this->final_policy.reset();
  } else {
    this->final_attrlist.reset();
  }
}

void Driver::set_policy(OpenABETreeNode *subtree) {
  if (this->final_policy == nullptr) {
    this->final_policy = std::unique_ptr<OpenABEPolicy>(new OpenABEPolicy);
    this->final_policy->setRootNode(subtree);
  } else {
    this->final_policy->setRootNode(subtree);
  }
  if (this->debug)
    std::cout << "Final policy set!" << std::endl;
  this->final_policy->setDuplicateInfo(this->attr_count, this->attr_dup);
  if (this->attr_prefix.size() > 0) {
    this->final_policy->setPrefixSet(this->attr_prefix);
  }
  this->final_policy->setCompactString(this->original_input);
}

void Driver::set_attrlist(std::vector<std::string> *attr_list) {
  if (this->debug) {
    cout << "Length: " << attr_list->size() << endl;
    for (auto &l : *attr_list) {
      cout << "ATTR: " << l << endl;
    }
    cout << "Original Attr Len: " << orig_attributes.size() << endl;
    for (auto &j : orig_attributes) {
      cout << "ATTR: " << j << endl;
    }
    cout << "Prefix set length: " << attr_prefix.size() << endl;
    for (auto &i : attr_prefix) {
      cout << "PREFIX: " << i << endl;
    }

    cout << "Date Prefix set length: " << date_prefix.size() << endl;
    for (auto &i : date_prefix) {
      cout << "PREFIX: " << i << endl;
    }
  }
  this->final_attrlist.reset(new OpenABEAttributeList);
  this->final_attrlist->setAttributes(*attr_list, orig_attributes, attr_prefix);
  if (attr_list != nullptr)
    delete attr_list;
  return;
}

// handler for LEAF '=' number
vector<string> *Driver::attr_num(const std::string &c, OpenABEUInteger *number) {
  vector<string> *attrs = new vector<string>();
  if (this->attr_count[c] >= 1) {
      if (this->debug)
          cerr << "'" << c << "' already specified as an attribute. Excluding from attribute list." << endl;
      return attrs;
  }
  assign_stmt(*attrs, c, *number);

  stringstream ss;
  ss << c << ASSIGN_EQ << *number;
  orig_attributes.push_back(ss.str());
  return attrs;
}

vector<string> *Driver::set_date_in_attrlist(const std::string &prefix,
                                             const std::string &month,
                                             OpenABEUInteger *m, OpenABEUInteger *d,
                                             OpenABEUInteger *y) {
  uint32_t s_days = validate_date(prefix, m, d, y);
  stringstream ss;
  ss << prefix << ASSIGN_EQ << month << " " << *d << ", " << *y;

  OpenABEUInteger ui(s_days, 32);
  vector<string> *attrs = new vector<string>();
  if (this->date_prefix.count(prefix) == 0) {
      const string attr = prefix + COLON + TIME_KEYWORD;
      assign_stmt(*attrs, attr, ui);
      orig_attributes.push_back(ss.str());
      this->date_prefix.insert(prefix);
  }
  return attrs;
}

bool Driver::parse_attribute(const std::string &c) {
  pair<string, string> attr = check_attribute(c);
  const string prefix = attr.first;
  const string attribute = attr.second;
  if (this->attr_count.count(c) == 0) {
    // first time, set to 1
    this->attr_count[c] = 1;
  } else { // already exist in list, so increment by 1
    return false;
  }

  if (prefix != "") {
    this->attr_prefix.insert(prefix);
  }

  return true;
}

vector<string> *Driver::leaf_attr(const std::string &c) {
  if (this->debug) {
    cout << "Parse as leaf attribute: " << c << endl;
  }
  // record prefix of attributes (if applicable)
  if (parse_attribute(c)) {
    vector<string> *attrs = new vector<string>();
    attrs->push_back(c);
    return attrs;
  }
  return nullptr;
}

std::vector<std::string> *Driver::concat_attr(std::vector<std::string> *attr1,
                                              std::vector<std::string> *attr2) {
  if (attr1 == nullptr) {
    attr1 = new vector<string>();
  }
  if (attr2 != nullptr) {
    for (auto &j : *attr2)
      attr1->push_back(j);
  }

  return attr1;
}

OpenABETreeNode *Driver::leaf_node(const std::string &c) {
  int index = 0;
  if (this->debug) {
    cout << "Constructing leaf node: " << c << endl;
  }
  pair<string, string> attr = check_attribute(c);
  const string prefix = attr.first;
  const string attribute = attr.second;

  if (this->attr_count.count(c) == 0) {
    // first time, set to 1
    this->attr_count[c] = 1;
  } else { // already exist, so increment by 1
    index = this->attr_count[c];
    this->attr_count[c] += 1;
    this->attr_dup.insert(c);
  }

  if (prefix != "") {
    this->attr_prefix.insert(prefix);
  }

  return new OpenABETreeNode(attribute, prefix, index);
}

OpenABETreeNode *Driver::kof2_tree(int k, OpenABETreeNode *l, OpenABETreeNode *r) {
  OpenABETreeNode *rootNode = new OpenABETreeNode();
  zGateType node_type;

  switch (k) {
  case 1:
    node_type = GATE_TYPE_OR;
    break;
  case 2:
    node_type = GATE_TYPE_AND;
    break;
  default:
    node_type = GATE_TYPE_THRESHOLD;
    break;
  }

  rootNode->setNodeType(node_type);
  rootNode->addSubnode(l);
  rootNode->addSubnode(r);
  rootNode->setThresholdValue(k);
  if (this->debug) {
    cout << "Constructing " << OpenABETreeNode_ToString(node_type) << " type.\n"
         << endl;
  }
  return rootNode;
}

OpenABETreeNode *Driver::kofn_tree(uint32_t threshold_k,
                               std::vector<OpenABETreeNode *> &attributeList) {
  OpenABETreeNode *rootNode = new OpenABETreeNode();
  zGateType node_type;
  size_t k;

  switch (threshold_k) {
  case 1:
    node_type = GATE_TYPE_OR;
    break;
  case 2:
    node_type = GATE_TYPE_AND;
    break;
  default:
    node_type = GATE_TYPE_THRESHOLD;
    break;
  }

  rootNode->setNodeType(node_type);
  for (k = 0; k < attributeList.size(); k++) {
    if (this->debug)
      std::cout << "Subnode " << k << ": " << attributeList[k]->toString()
                << std::endl;
    rootNode->addSubnode(attributeList[k]);
  }
  rootNode->setThresholdValue(threshold_k);
  if (this->debug)
    std::cout << "Constructing " << OpenABETreeNode_ToString(node_type)
              << " type.\n" << std::endl;
  return rootNode;
}

OpenABEUInteger *create_expint(uint32_t value, uint16_t bits) {
  return new OpenABEUInteger(value, bits);
}

OpenABEUInteger *create_flexint(uint32_t value) {
  return new OpenABEUInteger(value, MAX_INT_BITS);
}

bool checkValidBit(uint32_t value, uint32_t bits) {
  if (bits < 4 || bits > 32) {
    std::cerr << "must be equal to or greater than 4 and no more than 32 bits."
              << std::endl;
    return false;
  } else {
    bool isPowerTwo = (!(bits & (bits - 1)));
    if (!isPowerTwo) {
      std::cerr << "'" << bits << "' bits not a power of two." << std::endl;
      return false;
    }
    // check if 'value' is within range of bits!
    // uint32_t max_value = pow(2, bits)-1;
    uint32_t max_value = 0;
    switch (bits) {
        case 4:
           max_value = max_4bits;
           break;
        case 8:
           max_value = max_8bits;
           break;
        case 16:
           max_value = max_16bits;
           break;
        case 32:
           max_value = max_32bits;
           break;
        // case 64: max_value = max_64bits;
        //         break;
        default:
           std::cerr << "checkValidBit: missing bits in switch statement"
                     << std::endl;
           break;
    }
    if (value > max_value) {
      std::cerr << "cannot represent all of '" << value << "' using " << bits
                << " bits only." << endl;
      return false;
    }
  }

  return true;
}

OpenABETreeNode *Driver::bit_marker_list(bool flex, bool gt, std::string attr,
                                     int bits, uint32_t value) {
  OpenABETreeNode *p = NULL;
  int i;

  i = 0;
  while (gt ? (((uint32_t)1) << i & value) : !(((uint32_t)1) << i & value))
    i++;

  p = this->leaf_node(bit_marker(flex, attr, i, gt, bits));
  for (i = i + 1; i < bits; i++) {
    if (gt) {
      p = this->kof2_tree(((uint32_t)1 << i & value) ? 2 : 1,
                          this->leaf_node(bit_marker(flex, attr, i, gt, bits)),
                          p);
    } else {
      p = this->kof2_tree(((uint32_t)1 << i & value) ? 1 : 2,
                          this->leaf_node(bit_marker(flex, attr, i, gt, bits)),
                          p);
    }
  }

  return p;
}

OpenABETreeNode *Driver::flexint_leader(bool gt, std::string attr, uint32_t value) {
  // printf("called flexint_leader: gt=%d, attr=%s, value=%d\n", gt, attr,
  // value);
  int k;
  std::vector<OpenABETreeNode *> attributes;
  uint32_t i = 0;

  for (k = 2; k <= 16; k *= 2) {
    if ((gt && ((uint32_t)1 << k) > value) ||
        (!gt && ((uint32_t)1 << k) >= value)) {
      attributes.push_back(this->leaf_node(
          attr + FLEXINT + to_string(gt ? value + 1 : value - 1)));
    }
    i++;
  }

  if (i == 0) {
    return NULL;
  } else if (i == 1) {
    return attributes[0];
  }

  return this->kofn_tree((gt ? 1 : i), attributes);
}

OpenABETreeNode *Driver::cmp_policy(OpenABEUInteger *number, bool gt,
                                std::string attr) {
  OpenABETreeNode *p = NULL;

  /* create the subtree */
  int bits = number->getBits();
  bool flex = bits == 0 ? true : false;
  uint32_t value = number->getVal();
  //                                        (value >= ((uint64_t)1 << 32) ? 64
  //                                          :
  p = this->bit_marker_list(
      flex, gt, attr,
      bits ? bits : (value >= ((uint32_t)1 << 16)
                         ? 32
                         : value >= ((uint32_t)1 << 8)
                               ? 16
                               : value >= ((uint32_t)1 << 4)
                                     ? 8
                                     : value >= ((uint32_t)1 << 2) ? 4 : 2),
      value);
  return p;
}

std::string bit_marker(bool flex, std::string base, int bit, int val,
                       int bit_count) {
  std::string lx, rx, s;
  std::stringstream ss;
  lx = std::string(32 - bit - 1, 'x');
  rx = std::string(bit, 'x');
  // s = string(base, lx, !!val, rx);
  s = "";
  if (flex) {
    // flexint
    s = base + FLEXINT + lx;
  } else {
    // expint (4 up to 32)
    ss << std::setw(2) << std::setfill('0') << to_string(bit_count);
    s = base + EXPINT + ss.str() + "_" + lx;
  }
  // s += to_string(!!val) + rx;
  s += to_string(val ? 1 : 0) + rx;
  return s;
}

OpenABETreeNode *Driver::eq_policy(const std::string &c, OpenABEUInteger *number) {
  OpenABETreeNode *p = NULL;
  int bits = number->getBits();
  bool flex = bits ? false : true;
  int bit_count = bits ? bits : 32;

  std::bitset<32> num(number->getVal());
  // std::cout << "flex: " << flex << ", bit_count: " << bit_count << std::endl;
  // std::cout << "Bits: " << num << std::endl;
  int last = flex ? num.size() : bit_count;
  // std::cout << "Bit rep: " << num[last];
  p = this->leaf_node(bit_marker(flex, c, last - 1, num[last - 1], bit_count));

  for (int i = last - 1; i > 0; i--) {
    // std::cout << num[i-1];
    p = this->kof2_tree(2, p, this->leaf_node(bit_marker(
                                  flex, c, i - 1, num[i - 1], bit_count)));
  }
  // std::cout << std::endl;
  return p;
}

OpenABETreeNode *Driver::lt_policy(const std::string &attr, OpenABEUInteger *number) {
  return this->cmp_policy(number, false, attr);
}

OpenABETreeNode *Driver::gt_policy(const std::string &attr, OpenABEUInteger *number) {
  return this->cmp_policy(number, true, attr);
}

OpenABETreeNode *Driver::le_policy(const std::string &attr, OpenABEUInteger *number) {
  *number += 1;
  return this->cmp_policy(number, false, attr);
}

OpenABETreeNode *Driver::ge_policy(const std::string &attr, OpenABEUInteger *number) {
  *number -= 1;
  return this->cmp_policy(number, true, attr);
}

OpenABETreeNode *Driver::range_policy(const std::string &c, OpenABEUInteger *min_num,
                                  OpenABEUInteger *max_num) {
  if (min_num->getVal() > max_num->getVal()) {
    throw OpenABE_ERROR_INVALID_RANGE_NUMBERS;
  } else if (min_num->getBits() != max_num->getBits()) {
    throw OpenABE_ERROR_INVALID_MISMATCH_BITS;
  }
  // translate to (LEAF > min_num AND LEAF < max_num)
  OpenABETreeNode *rootNode = new OpenABETreeNode();
  OpenABETreeNode *l = this->gt_policy(c, min_num);
  OpenABETreeNode *r = this->lt_policy(c, max_num);
  rootNode->setNodeType(GATE_TYPE_AND);
  rootNode->addSubnode(l);
  rootNode->addSubnode(r);
  rootNode->setThresholdValue(2);
  return rootNode;
}

OpenABETreeNode *Driver::range_incl_policy(const std::string &c,
                                       OpenABEUInteger *min_num,
                                       OpenABEUInteger *max_num) {
  if (min_num->getVal() > max_num->getVal()) {
    throw OpenABE_ERROR_INVALID_RANGE_NUMBERS;
  } else if (min_num->getBits() != max_num->getBits()) {
    throw OpenABE_ERROR_INVALID_MISMATCH_BITS;
  }
  // translate to (LEAF >= min_num AND LEAF <= max_num)
  OpenABETreeNode *rootNode = new OpenABETreeNode();
  OpenABETreeNode *l = this->ge_policy(c, min_num);
  OpenABETreeNode *r = this->le_policy(c, max_num);
  rootNode->setNodeType(GATE_TYPE_AND);
  rootNode->addSubnode(l);
  rootNode->addSubnode(r);
  rootNode->setThresholdValue(2);
  return rootNode;
}

static bool is_valid_date(int month, int day, int year) {
  // gregorian calendar started in 1582
  if (!(1582 <= year))
    return false;
  if (!(1 <= month && month <= 12))
    return false;
  if (!(1 <= day && day <= 31))
    return false;
  if ((day == 31) &&
      (month == 2 || month == 4 || month == 6 || month == 9 || month == 11))
    return false;
  if ((day == 30) && (month == 2))
    return false;
  if ((month == 2) && (day == 29) && (year % 4 != 0))
    return false;
  if ((month == 2) && (day == 29) && (year % 400 == 0))
    return true;
  if ((month == 2) && (day == 29) && (year % 100 == 0))
    return false;
  if ((month == 2) && (day == 29) && (year % 4 == 0))
    return true;

  return true;
}

OpenABEUInteger *get_month(const string &month) {
  int m = -1;
  if (month == "January" || month == "Jan")
    m = 1;
  else if (month == "February" || month == "Feb")
    m = 2;
  else if (month == "March" || month == "Mar")
    m = 3;
  else if (month == "April" || month == "Apr")
    m = 4;
  else if (month == "May")
    m = 5;
  else if (month == "June" || month == "Jun")
    m = 6;
  else if (month == "July" || month == "Jul")
    m = 7;
  else if (month == "August" || month == "Aug")
    m = 8;
  else if (month == "September" || month == "Sep")
    m = 9;
  else if (month == "October" || month == "Oct")
    m = 10;
  else if (month == "November" || month == "Nov")
    m = 11;
  else if (month == "December" || month == "Dec")
    m = 12;
  else
    m = 0;
  return new OpenABEUInteger(m, MAX_INT_BITS);
}

uint32_t validate_date(const std::string &prefix, OpenABEUInteger *m,
                       OpenABEUInteger *d, OpenABEUInteger *y) {
  // check for valid date. Also, make sure no bits specified for year or day.
  // If flexints originally, then turn into appropriate expints
  //    cout << "Prefix: " << prefix << endl;
  //    cout << "Month: " << m->getVal() << endl;
  //    cout << "Day: " << d->getVal() << endl;
  //    cout << "Year: " << y->getVal() << endl;
  if (prefix == MONTH_KEYWORD || prefix == DAY_KEYWORD ||
      prefix == YEAR_KEYWORD) {
        throw OpenABE_ERROR_INVALID_PREFIX_SPECIFIED;
  }

  if (!(m->isFlexInt() && d->isFlexInt() && y->isFlexInt())) {
    throw OpenABE_ERROR_INVALID_ATTRIBUTE_STRUCTURE;
  }

  if (!is_valid_date(m->getVal(), d->getVal(), y->getVal())) {
    throw OpenABE_ERROR_INVALID_DATE_SPECIFIED;
  }

  // reject if before epoch
  if (y->getVal() < EPOCH_YEAR) {
    throw OpenABE_ERROR_INVALID_DATE_BEFORE_EPOCH;
  }

  struct tm t = {0};
  t.tm_year = y->getVal() - 1900;
  t.tm_mon = m->getVal() - 1;
  t.tm_mday = d->getVal();
  time_t s = mktime(&t);

  uint32_t in_days = (uint32_t)(s / DAY_IN_SECS);
  return in_days;
}

void validate_range_date(const std::string &prefix, OpenABEUInteger *m,
                         OpenABEUInteger *min_d, OpenABEUInteger *max_d,
                         OpenABEUInteger *y) {
  if (prefix == MONTH_KEYWORD || prefix == DAY_KEYWORD ||
      prefix == YEAR_KEYWORD) {
    throw OpenABE_ERROR_INVALID_PREFIX_SPECIFIED;
  }

  if (!(m->isFlexInt() && min_d->isFlexInt() && max_d->isFlexInt() &&
        y->isFlexInt())) {
    throw OpenABE_ERROR_INVALID_ATTRIBUTE_STRUCTURE;
  }

  if (!is_valid_date(m->getVal(), min_d->getVal(), y->getVal())) {
    throw OpenABE_ERROR_INVALID_DATE_SPECIFIED;
  }

  if (!is_valid_date(m->getVal(), max_d->getVal(), y->getVal())) {
    throw OpenABE_ERROR_INVALID_DATE_SPECIFIED;
  }

  // reject if before epoch
  if (y->getVal() < EPOCH_YEAR) {
    throw OpenABE_ERROR_INVALID_DATE_BEFORE_EPOCH;
  }
}

OpenABETreeNode *Driver::set_date_in_policy(const std::string &prefix,
                                        OpenABEUInteger *m, OpenABEUInteger *d,
                                        OpenABEUInteger *y) {
  // date = {Month} {Day}, {Year}
  uint32_t s = validate_date(prefix, m, d, y);
  string attr = "";
  if (prefix != TIME_KEYWORD)
    attr += prefix + COLON + TIME_KEYWORD;
  else
    attr += prefix;

  OpenABEUInteger ui(s, 32);
  OpenABETreeNode *rootNode = this->eq_policy(attr, &ui);
  return rootNode;
}

OpenABETreeNode *Driver::gt_date_in_policy(const std::string &prefix,
                                       OpenABEUInteger *m, OpenABEUInteger *d,
                                       OpenABEUInteger *y) {
  // date > {Month} {Day}, {Year}
  uint32_t s = validate_date(prefix, m, d, y);
  string attr = "";
  if (prefix != TIME_KEYWORD)
    attr += prefix + COLON + TIME_KEYWORD;
  else
    attr += prefix;

  OpenABEUInteger ui(s, 32);
  OpenABETreeNode *rootNode = this->gt_policy(attr, &ui);
  return rootNode;
}

OpenABETreeNode *Driver::ge_date_in_policy(const std::string &prefix,
                                       OpenABEUInteger *m, OpenABEUInteger *d,
                                       OpenABEUInteger *y) {
  // date >= {Month} {Day}, {Year}
  uint32_t s = validate_date(prefix, m, d, y);
  string attr = "";
  if (prefix != TIME_KEYWORD)
    attr += prefix + COLON + TIME_KEYWORD;
  else
    attr += prefix;

  OpenABEUInteger ui(s, 32);
  OpenABETreeNode *rootNode = this->ge_policy(attr, &ui);
  return rootNode;
}

OpenABETreeNode *Driver::lt_date_in_policy(const std::string &prefix,
                                       OpenABEUInteger *m, OpenABEUInteger *d,
                                       OpenABEUInteger *y) {
  // date < {Month} {Day}, {Year}
  uint32_t s = validate_date(prefix, m, d, y);
  string attr = "";
  if (prefix != TIME_KEYWORD)
    attr += prefix + COLON + TIME_KEYWORD;
  else
    attr += prefix;

  OpenABEUInteger ui(s, 32);
  OpenABETreeNode *rootNode = this->lt_policy(attr, &ui);
  return rootNode;
}

OpenABETreeNode *Driver::le_date_in_policy(const std::string &prefix,
                                       OpenABEUInteger *m, OpenABEUInteger *d,
                                       OpenABEUInteger *y) {
  // date < {Month} {Day}, {Year}
  uint32_t s = validate_date(prefix, m, d, y);
  string attr = "";
  if (prefix != TIME_KEYWORD)
    attr += prefix + COLON + TIME_KEYWORD;
  else
    attr += prefix;

  OpenABEUInteger ui(s, 32);
  OpenABETreeNode *rootNode = this->le_policy(attr, &ui);
  return rootNode;
}

OpenABETreeNode *Driver::range_date_in_policy(const std::string &prefix,
                                          OpenABEUInteger *m, OpenABEUInteger *min_d,
                                          OpenABEUInteger *max_d, OpenABEUInteger *y) {
  if (min_d->getVal() > max_d->getVal()) {
    throw OpenABE_ERROR_INVALID_RANGE_NUMBERS;
  }
  validate_range_date(prefix, m, min_d, max_d, y);

  struct tm t1 = {0};
  t1.tm_year = y->getVal() - 1900;
  t1.tm_mon = m->getVal() - 1;
  t1.tm_mday = min_d->getVal();
  time_t s1 = mktime(&t1);
  uint32_t s1_days = s1 / DAY_IN_SECS;

  t1.tm_mday = max_d->getVal();
  time_t s2 = mktime(&t1);
  uint32_t s2_days = s2 / DAY_IN_SECS;

  string attr = "";
  if (prefix != TIME_KEYWORD)
    attr += prefix + COLON + TIME_KEYWORD;
  else
    attr += prefix;

  OpenABEUInteger ui_min((uint32_t)s1_days, 32), ui_max((uint32_t)s2_days, 32);
  OpenABETreeNode *l = this->ge_policy(attr, &ui_min);
  OpenABETreeNode *r = this->le_policy(attr, &ui_max);
  OpenABETreeNode *rootNode = new OpenABETreeNode();
  rootNode->setNodeType(GATE_TYPE_AND);
  rootNode->addSubnode(l);
  rootNode->addSubnode(r);
  rootNode->setThresholdValue(2);

  return rootNode;
}

std::ostream &Driver::print(std::ostream &stream) {
  stream << this->final_policy->getRootNode()->toString() << "\n";
  return (stream);
}

////////////////////// Driver for OpenABEPolicy //////////////////////

bool assign_stmt(std::vector<std::string> &attributeList, const std::string &c,
                 OpenABEUInteger &number) {
  // std::cout << "number: " << number << "\n";
  int bits = number.getBits();
  bool flex = bits ? false : true;
  int bit_count = bits ? bits : 32;

  if (!flex && !checkValidBit(number.getVal(), bits)) {
    return false;
  }

  std::bitset<32> num(number.getVal());
  // std::cout << "bit rep: " << num << "\n";

  int last = flex ? num.size() : bit_count;
  if (last < 32) {
    last += 2; // bump up to fully capture bits necessary for <=,>= type trees
  }
  // std::cout << "last = " << last << std::endl;
  // std::cout << "num[" << last << "] = " << num[last-1] << std::endl;
  attributeList.push_back(
      bit_marker(flex, c, last - 1, num[last - 1], bit_count));

  for (int i = last - 1; i > 0; i--) {
    attributeList.push_back(bit_marker(flex, c, i - 1, num[i - 1], bit_count));
  }
  return true;
}

pair<string, string> check_attribute(const string &c) {
  std::string attribute = "", prefix = "";
  size_t found = c.find(COLON);
  if (found != std::string::npos) {
    // contains a ':'
    vector<string> list = split(c, COLON);
    size_t len = list.size();
    prefix = list[0];
    if (len == 2) {
      // break down into two parts
      attribute = list[1];
    } else if (len >= 3) {
      // remaining are treated as attribute
      for (size_t i = 1; i < len; i++) {
        attribute += list[i];
        if (i != (len - 1)) {
          attribute += COLON;
        }
      }
    } else {
      // throw an error here
      throw OpenABE_ERROR_INVALID_ATTRIBUTE_STRUCTURE;
    }
  } else {
    // continue as before and means no prefix was specified
    attribute = c;
  }

  return make_pair(prefix, attribute);
}

} 
