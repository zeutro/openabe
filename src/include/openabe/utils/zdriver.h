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
/// \file   zdriver.h
///
/// \brief  Class definition for OpenABE policy parser.
///
/// \author J. Ayo Akinyele
///

#ifndef __ZDRIVER_H__
#define __ZDRIVER_H__

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <iomanip>
#include <sstream>

#define COLON     ':'
#define FLEXINT   "_flexint_"
#define EXPINT    "_expint"
#define POLICY_PREFIX   "[0]: "
#define ATTRLIST_PREFIX "[1]: "
#define ASSIGN_EQ    "="
#define MONTH_KEYWORD  "month"
#define DAY_KEYWORD    "day"
#define YEAR_KEYWORD   "year"
#define TIME_KEYWORD   "time"
#define EPOCH_YEAR     1970

#define MONTH_BITS  4
#define DAY_BITS    8
#define YEAR_BITS   16

static const uint32_t max_4bits = 0xf;
static const uint32_t max_8bits = 0xff;
static const uint32_t max_16bits = 0xffff;
static const uint32_t max_32bits = 0xffffffff;
//static const uint32_t max_64bits = 0xffffffffffffffff;

/** The namespace is used to encapsulate the three parser classes
 * oabe::Parser, oabe::Scanner and oabe::Driver */
namespace oabe {

class OpenABEPolicy;
class OpenABEAttributeList;
class OpenABETreeNode;
class OpenABEUInteger;
/** The Driver class brings together all components. It creates an instance of
 * the Parser and Scanner classes and connects them. Then the input stream is
 * fed into the scanner object and the parser gets it's token
 * sequence. Furthermore the driver object is available in the grammar rules as
 * a parameter. Therefore the driver class contains a reference to the
 * structure into which the parsed data is saved. */
class Driver {
public:
  Driver(bool);
  ~Driver();

  /// enable debug output in the flex scanner
  bool trace_scanning;

  /// enable debug output in the bison parser
  bool trace_parsing;

  /// stream name (file or input stream) used for error messages.
  std::string streamname;

  /** Invoke the scanner and parser for a stream.
   * @param in	input stream
   * @param sname	stream name for error messages
   * @return		true if successfully parsed
   */
  bool parse_stream(std::istream& in,
                    const std::string& sname = "stream input");

  /** Invoke the scanner and parser on an input string.
   * @param input	input string
   * @param sname	stream name for error messages
   * @return		true if successfully parsed
   */
  bool parse_string(const std::string& prefix, const std::string& input,
                    const std::string& sname = "string stream");

  /** Invoke the scanner and parser on a file. Use parse_stream with a
   * std::ifstream if detection of file reading errors is required.
   * @param filename	input file name
   * @return		true if successfully parsed
   */
  // bool parse_file(const std::string& filename);

  // To demonstrate pure handling of parse errors, instead of
  // simply dumping them on the standard error output, we will pass
  // them to the driver using the following two member functions.

  /** Error handling with associated line number. This can be modified to
   * output the error e.g. to a dialog box. */
  void error(const class location& l, const std::string& m);

  /** General error handling. This can be modified to output the error
   * e.g. to a dialog box. */
  // void error(const std::string& m);

  /** Pointer to the current lexer instance, this is used to connect the
   * parser to the scanner. It is used in the yylex macro. */
  class Scanner* lexer;

  /* helper functions */
  std::unique_ptr<OpenABEPolicy> getPolicy() { return std::move(this->final_policy); }
  std::unique_ptr<OpenABEAttributeList> getAttributeList() { return std::move(this->final_attrlist); }
  void set_policy(OpenABETreeNode *subtree);
  void set_attrlist(std::vector<std::string> *list);
  OpenABETreeNode* leaf_node(const std::string &c);
  bool parse_attribute(const std::string& c);
  std::vector<std::string>* leaf_attr(const std::string& c);
  std::vector<std::string>* concat_attr(std::vector<std::string> *attr1, std::vector<std::string> *attr2);
  std::vector<std::string>* attr_num(const std::string &c, OpenABEUInteger *number);
  std::vector<std::string>* set_date_in_attrlist(const std::string& prefix, const std::string& month,
                                                 OpenABEUInteger *m, OpenABEUInteger *d, OpenABEUInteger *y);
  OpenABETreeNode* kof2_tree(int k, OpenABETreeNode *l, OpenABETreeNode *r);
  OpenABETreeNode* kofn_tree(uint32_t threshold_k, std::vector<OpenABETreeNode*>& attributeList);

  OpenABEUInteger* create_expint(uint32_t value, uint16_t bits);
  OpenABEUInteger* create_flexint(uint32_t value);
  OpenABETreeNode* eq_policy(const std::string &c, OpenABEUInteger *number);
  OpenABETreeNode* lt_policy(const std::string &c, OpenABEUInteger *number);
  OpenABETreeNode* gt_policy(const std::string &c, OpenABEUInteger *number);
  OpenABETreeNode* le_policy(const std::string &c, OpenABEUInteger *number);
  OpenABETreeNode* ge_policy(const std::string &c, OpenABEUInteger *number);
  OpenABETreeNode* range_policy(const std::string& c, OpenABEUInteger *min_num, OpenABEUInteger *max_num);
  OpenABETreeNode* range_incl_policy(const std::string& c, OpenABEUInteger *min_num, OpenABEUInteger *max_num);
  OpenABETreeNode* set_date_in_policy(const std::string& prefix, OpenABEUInteger *m, OpenABEUInteger *d, OpenABEUInteger *y);
  OpenABETreeNode* gt_date_in_policy(const std::string& prefix, OpenABEUInteger *m, OpenABEUInteger *d, OpenABEUInteger *y);
  OpenABETreeNode* ge_date_in_policy(const std::string& prefix, OpenABEUInteger *m, OpenABEUInteger *d, OpenABEUInteger *y);
  OpenABETreeNode* lt_date_in_policy(const std::string& prefix, OpenABEUInteger *m, OpenABEUInteger *d, OpenABEUInteger *y);
  OpenABETreeNode* le_date_in_policy(const std::string& prefix, OpenABEUInteger *m, OpenABEUInteger *d, OpenABEUInteger *y);
  OpenABETreeNode* range_date_in_policy(const std::string& prefix, OpenABEUInteger *m, OpenABEUInteger *min_d,
                                    OpenABEUInteger *max_d, OpenABEUInteger *y);
  std::ostream& print(std::ostream &stream);

private:
  // counter for every attribute that occurs in the tree
  std::map<std::string, int> attr_count;
  // records the subset of attributes that are indeed duplicated
  std::set<std::string> attr_dup, attr_prefix, date_prefix;
  std::vector<std::string> orig_attributes;
  // store the original input (in case it includes comparison operators)
  std::string original_input;

  bool debug, isPolicy;
  std::unique_ptr<OpenABEPolicy> final_policy;
  std::unique_ptr<OpenABEAttributeList> final_attrlist;
  // helper functions for non-numerical attributes
  OpenABETreeNode* bit_marker_list(bool flex, bool gt, std::string attr, int bits, uint32_t value);
  OpenABETreeNode* cmp_policy(OpenABEUInteger* number, bool gt, std::string attr);
  OpenABETreeNode* flexint_leader(bool gt, std::string attr, uint32_t value);
};

std::pair<std::string,std::string> check_attribute(const std::string& c);
uint32_t validate_date(const std::string& prefix, OpenABEUInteger *m, OpenABEUInteger *d, OpenABEUInteger *y);
void validate_range_date(const std::string& prefix, OpenABEUInteger *m, OpenABEUInteger *min_d,
                         OpenABEUInteger *max_d, OpenABEUInteger *y);
OpenABEUInteger* create_expint(uint32_t value, uint16_t bits);
OpenABEUInteger* create_flexint(uint32_t value);
bool checkValidBit(uint32_t value, uint32_t bits);
OpenABEUInteger* get_month(const std::string& month);
bool assign_stmt(std::vector<std::string> &attributeList, const std::string &c, OpenABEUInteger &number);
std::string  bit_marker(bool flex, std::string base, int bit, int val, int bit_count);
inline std::string MakeUniqueLabel(const std::string base,
                                   const std::string keyword,
                                   std::string unique)
{
  return base + "_" + keyword + "_" + unique;
}

}

#endif // __ZDRIVER_H__
