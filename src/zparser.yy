/** \file zparser.yy Contains the OpenABEPolicy and OpenABEAttributeList Bison parser source */

%{ /*** C/C++ Declarations ***/

#include <stdio.h>
#include <string>
#include <vector>

#include <openabe/zobject.h>
#include <openabe/utils/zerror.h>
#include <openabe/utils/zconstants.h>
#include <openabe/utils/zbytestring.h>
#include <openabe/utils/zfunctioninput.h>
#include <openabe/utils/zinteger.h>
#include <openabe/utils/zattributelist.h>
#include <openabe/utils/zpolicy.h>

%}

/*** yacc/bison Declarations ***/

/* Require bison 3.0 or later */
%require "3.0"

/* add debug output code to generated parser. disable this for release
 * versions. */
%debug

/* start symbol is named "start" */
%start start

/* write out a header file containing the token defines */
%defines

/* use newer C++ skeleton file */
%skeleton "lalr1.cc"

/* namespace to enclose parser in */
%name-prefix "oabe"

/* set the parser's class identifier */
%define api.parser.class {Parser}

/* keep track of the current position within the input */
%locations
%initial-action
{
    // initialize the initial location object
    @$.begin.filename = @$.end.filename = &driver.streamname;
};

/* The driver is passed by reference to the parser and to the scanner. This
 * provides a simple but effective pure interface, not relying on global
 * variables. */
%parse-param { class Driver& driver }

/* verbose error messages */
%error-verbose

 /*** BEGIN EXAMPLE - Change the example grammar's tokens below ***/

%union {
    std::string*		stringVal;
    class OpenABETreeNode*	treeNode;
    std::vector<std::string>* oabeAttrList;    
    uint32_t            uintVal;
    class OpenABEUInteger*  uInteger;
}

%token	             END  0   "end of file"
%token	             EOL      "end of line"
%token   <stringVal> LEAF     "string"
%token     <uintVal> UINT     "an integer"
%type     <uInteger> number   "OpenABEUInteger"
%type	  <treeNode> policy   "OpenABE tree node"
%type <oabeAttrList>  attrlist "OpenABE attribute list"

%left OR
%left AND  
%token OF  "of"
%token EQ  "=="
%token ASSIGN "="
%token LEQ "<="
%token GEQ ">="
%token ERROR "error"
%token START_POLICY   "[0]:"
%token START_ATTRLIST "[1]:"
%token IN "in"
%destructor { delete $$; } LEAF
%destructor { delete $$; } policy
%destructor { delete $$; } attrlist
%destructor { delete $$; } number

 /*** END EXAMPLE - Change the example grammar's tokens above ***/

%{

#include <openabe/utils/zdriver.h>
#include <openabe/utils/zscanner.h>

/* this "connects" the bison parser in the driver to the flex scanner class
 * object. it defines the yylex() function call to pull the next token from the
 * current lexer object of the driver context. */
#undef yylex
#define yylex driver.lexer->lex

%}

%% /*** Grammar Rules ***/

 /*** BEGIN EXAMPLE - Change the example grammar rules below ***/

start:
  START_POLICY policy  { driver.set_policy($2); } | 
  START_ATTRLIST attrlist { driver.set_attrlist($2); };

number:   UINT '#' UINT         {
                                   if (!oabe::checkValidBit($1, $3)) {
                                      YYERROR;
                                   } else {
                                      $$ = create_expint($1, $3);
                                   }
                                }
        | UINT                  { $$ = create_flexint($1); }

policy:   LEAF                  { $$ = driver.leaf_node(*$1); delete $1; }
        | policy OR policy      { $$ = driver.kof2_tree(1, $1, $3); }
        | policy AND policy     { $$ = driver.kof2_tree(2, $1, $3); }
        | LEAF '<' number       { $$ = driver.lt_policy(*$1, $3); delete $1; delete $3; }
        | LEAF '>' number       { $$ = driver.gt_policy(*$1, $3); delete $1; delete $3; }
        | LEAF LEQ number       { $$ = driver.le_policy(*$1, $3); delete $1; delete $3; }
        | LEAF GEQ number       { $$ = driver.ge_policy(*$1, $3); delete $1; delete $3; }
        | LEAF EQ number        { $$ = driver.eq_policy(*$1, $3); delete $1; delete $3; }
        | '(' policy ')'        { $$ = $2; }
        /* for range-types */
        | LEAF IN '(' number '-' number ')'
                { $$ = driver.range_policy(*$1, $4, $6); 
                  delete $1; delete $4; delete $6; 
                }
        | LEAF IN '{' number '-' number '}'
                { $$ = driver.range_incl_policy(*$1, $4, $6); 
                  delete $1; delete $4; delete $6; 
                }
        /* for date-types */
        | LEAF '=' LEAF number ',' number
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*$3)); 
                  $$ = driver.set_date_in_policy(*$1, month.get(), $4, $6); 
                  delete $1; delete $3; delete $4; delete $6;
                }
        | LEAF '=' LEAF number '-' number ',' number
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*$3)); 
                  $$ = driver.range_date_in_policy(*$1, month.get(), $4, $6, $8); 
                  delete $1; delete $3; delete $4; delete $6; delete $8;
                }
        | LEAF '>' LEAF number ',' number
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*$3)); 
                  $$ = driver.gt_date_in_policy(*$1, month.get(), $4, $6); 
                  delete $1; delete $3; delete $4; delete $6;
                }
        | LEAF '<' LEAF number ',' number
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*$3)); 
                  $$ = driver.lt_date_in_policy(*$1, month.get(), $4, $6); 
                  delete $1; delete $3; delete $4; delete $6;
                }
        | LEAF GEQ LEAF number ',' number
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*$3)); 
                  $$ = driver.ge_date_in_policy(*$1, month.get(), $4, $6); 
                  delete $1; delete $3; delete $4; delete $6;
                }
        | LEAF LEQ LEAF number ',' number
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*$3)); 
                  $$ = driver.le_date_in_policy(*$1, month.get(), $4, $6); 
                  delete $1; delete $3; delete $4; delete $6;
                }

attrlist:   LEAF                { $$ = driver.leaf_attr(*$1); delete $1; }
        | '|' attrlist          { $$ = driver.concat_attr($2, nullptr); }
        | attrlist '|'          { $$ = driver.concat_attr($1, nullptr); }
        | attrlist '|' attrlist { $$ = driver.concat_attr($1, $3); delete $3; }
        | LEAF '=' number       { $$ = driver.attr_num(*$1, $3); delete $1; delete $3; }
        | LEAF '=' LEAF number ',' number
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*$3)); 
                  $$ = driver.set_date_in_attrlist(*$1, *$3, month.get(), $4, $6); 
                  delete $1; delete $3; delete $4; delete $6;
                }
;



 /*** END EXAMPLE - Change the example grammar rules above ***/

%% /*** Additional Code ***/

void oabe::Parser::error(const Parser::location_type& l,
			    const std::string& m)
{
    driver.error(l, m);
}
