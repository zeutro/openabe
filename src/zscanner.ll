/** \file zscanner.ll Define the OpenABE policy Flex lexical scanner */

%{ /*** C/C++ Declarations ***/

#include <string>
#include <climits>
#include <openabe/utils/zscanner.h>

/* import the parser's token type into a local typedef */
typedef oabe::Parser::token token;
typedef oabe::Parser::token_type token_type;

/* By default yylex returns int, we use token_type. Unfortunately yyterminate
 * by default returns 0, which is not of token_type. */
#define yyterminate() return token::END

/* This disables inclusion of unistd.h, which is not available under Visual C++
 * on Win32. The C++ scanner uses STL streams instead. */
#define YY_NO_UNISTD_H

%}

/*** Flex Declarations and Options ***/

/* enable c++ scanner class generation */
%option c++

/* change the name of the scanner class. results in "OpenABEFlexLexer" */
%option prefix="OpenABE"

/* the manual says "somewhat more optimized" */
%option batch

/* enable scanner to generate debug output. disable this for release
 * versions. */
%option debug

/* no support for include files is planned */
%option yywrap nounput 

/* enables the use of start condition stacks */
%option stack

/* The following paragraph suffices to track locations accurately. Each time
 * yylex is invoked, the begin position is moved onto the end position. */
%{
#define YY_USER_ACTION  yylloc->columns(yyleng);
%}

%% /*** Regular Expressions Part ***/

 /* code to place at the beginning of yylex() */
%{
    // reset location
    yylloc->step();
%}

 /*** BEGIN EXAMPLE - Change the example lexer rules below ***/

[0-9]+ {
       errno = 0;
       unsigned long n = strtoul (yytext, NULL, 10);
       if (! (n < UINT_MAX && errno != ERANGE)) { /* 32-bit unsigned integers */
	       std::cerr << *yylloc << ": unsigned integer is out of range" << std::endl;
	       return token::ERROR;
       } else if ( n == 0 ) {
	       std::cerr << *yylloc << ": cannot build meaningful comparison trees with 0" << std::endl;
	       return token::ERROR;
       }
       yylval->uintVal = n;
       return token::UINT;
}

[A-Za-z/\\.\[\]$~][A-Za-z0-9_/\\,.\*\-:!~\[\]\&\$\#\@\%\^{}]* {
    yylval->stringVal = new std::string(yytext, yyleng);
    if(yylval->stringVal->compare("[0]:") == 0) {
         delete yylval->stringVal;
         return token::START_POLICY;    	
    } else if(yylval->stringVal->compare("[1]:") == 0) {
         delete yylval->stringVal;
         return token::START_ATTRLIST;
    } else if(yylval->stringVal->compare("or") == 0 || yylval->stringVal->compare("OR") == 0) {
         delete yylval->stringVal;
         return token::OR;
    } else if(yylval->stringVal->compare("and") == 0 || yylval->stringVal->compare("AND") == 0) {
         delete yylval->stringVal;	
         return token::AND;
    } else if(yylval->stringVal->compare("in") == 0 || yylval->stringVal->compare("IN") == 0) {
         delete yylval->stringVal;
         return token::IN;
    } else if(yylval->stringVal->find(EXPINT_KEYWORD) != std::string::npos) {
         std::cerr << *yylloc << ": '" << EXPINT_KEYWORD << "' is reserved and cannot be user-specified." << std::endl;
         return token::ERROR;
    } else {
         return token::LEAF;
    }
}

[<>=][=] {
    yylval->stringVal = new std::string(yytext, yyleng);
	if(yylval->stringVal->compare("<=") == 0) {
	     delete yylval->stringVal;	
	     return token::LEQ;
	} else if(yylval->stringVal->compare(">=") == 0) {
	     delete yylval->stringVal;
	     return token::GEQ;		
	} else if(yylval->stringVal->compare("==") == 0) {
	     delete yylval->stringVal;
	     return token::EQ;		
	} else {
	     delete yylval->stringVal;	
             std::cerr << *yylloc << ": invalid operator. Allowed operators: [<, <=, >, >=, ==]" << std::endl;
             return token::ERROR;
	}
}

 /* gobble up white-spaces */
[ \t\r]+ {
    yylloc->step();
}

 /* gobble up end-of-lines */
\n {
    yylloc->lines(yyleng); yylloc->step();
    return token::EOL;
}

 /* pass all other characters up to bison */
. {
    return static_cast<token_type>(*yytext);
}

 /*** END EXAMPLE - Change the example lexer rules above ***/

%% /*** Additional Code ***/

namespace oabe {

Scanner::Scanner(std::istream* in,
		 std::ostream* out)
    : OpenABEFlexLexer(in, out)
{
}

Scanner::~Scanner()
{
}

void Scanner::set_debug(bool b)
{
    yy_flex_debug = b;
}

}

/* This implementation of OpenABEFlexLexer::yylex() is required to fill the
 * vtable of the class OpenABEFlexLexer. We define the scanner's main yylex
 * function via YY_DECL to reside in the Scanner class instead. */

#ifdef yylex
#undef yylex
#endif

int OpenABEFlexLexer::yylex()
{
    std::cerr << "in OpenABEFlexLexer::yylex() !" << std::endl;
    return 0;
}

/* When the scanner receives an end-of-file indication from YY_INPUT, it then
 * checks the yywrap() function. If yywrap() returns false (zero), then it is
 * assumed that the function has gone ahead and set up `yyin' to point to
 * another input file, and scanning continues. If it returns true (non-zero),
 * then the scanner terminates, returning 0 to its caller. */

int OpenABEFlexLexer::yywrap()
{
    return 1;
}
