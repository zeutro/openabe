// A Bison parser, made by GNU Bison 3.8.2.

// Skeleton implementation for Bison LALR(1) parsers in C++

// Copyright (C) 2002-2015, 2018-2021 Free Software Foundation, Inc.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// As a special exception, you may create a larger work that contains
// part or all of the Bison parser skeleton and distribute that work
// under terms of your choice, so long as that work isn't itself a
// parser generator using the skeleton or a modified version thereof
// as a parser skeleton.  Alternatively, if you modify or redistribute
// the parser skeleton itself, you may (at your option) remove this
// special exception, which will cause the skeleton and the resulting
// Bison output files to be licensed under the GNU General Public
// License without this special exception.

// This special exception was added by the Free Software Foundation in
// version 2.2 of Bison.

// DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
// especially those whose name start with YY_ or yy_.  They are
// private implementation details that can be changed or removed.


// Take the name prefix into account.
#define yylex   oabelex

// First part of user prologue.
#line 3 "zparser.yy"
 /*** C/C++ Declarations ***/

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


#line 60 "zparser.tab.cc"


#include "zparser.tab.hh"

// Second part of user prologue.
#line 96 "zparser.yy"


#include <openabe/utils/zdriver.h>
#include <openabe/utils/zscanner.h>

/* this "connects" the bison parser in the driver to the flex scanner class
 * object. it defines the yylex() function call to pull the next token from the
 * current lexer object of the driver context. */
#undef yylex
#define yylex driver.lexer->lex


#line 79 "zparser.tab.cc"



#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> // FIXME: INFRINGES ON USER NAME SPACE.
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif


// Whether we are compiled with exception support.
#ifndef YY_EXCEPTIONS
# if defined __GNUC__ && !defined __EXCEPTIONS
#  define YY_EXCEPTIONS 0
# else
#  define YY_EXCEPTIONS 1
# endif
#endif

#define YYRHSLOC(Rhs, K) ((Rhs)[K].location)
/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

# ifndef YYLLOC_DEFAULT
#  define YYLLOC_DEFAULT(Current, Rhs, N)                               \
    do                                                                  \
      if (N)                                                            \
        {                                                               \
          (Current).begin  = YYRHSLOC (Rhs, 1).begin;                   \
          (Current).end    = YYRHSLOC (Rhs, N).end;                     \
        }                                                               \
      else                                                              \
        {                                                               \
          (Current).begin = (Current).end = YYRHSLOC (Rhs, 0).end;      \
        }                                                               \
    while (false)
# endif


// Enable debugging if requested.
#if OABEDEBUG

// A pseudo ostream that takes yydebug_ into account.
# define YYCDEBUG if (yydebug_) (*yycdebug_)

# define YY_SYMBOL_PRINT(Title, Symbol)         \
  do {                                          \
    if (yydebug_)                               \
    {                                           \
      *yycdebug_ << Title << ' ';               \
      yy_print_ (*yycdebug_, Symbol);           \
      *yycdebug_ << '\n';                       \
    }                                           \
  } while (false)

# define YY_REDUCE_PRINT(Rule)          \
  do {                                  \
    if (yydebug_)                       \
      yy_reduce_print_ (Rule);          \
  } while (false)

# define YY_STACK_PRINT()               \
  do {                                  \
    if (yydebug_)                       \
      yy_stack_print_ ();                \
  } while (false)

#else // !OABEDEBUG

# define YYCDEBUG if (false) std::cerr
# define YY_SYMBOL_PRINT(Title, Symbol)  YY_USE (Symbol)
# define YY_REDUCE_PRINT(Rule)           static_cast<void> (0)
# define YY_STACK_PRINT()                static_cast<void> (0)

#endif // !OABEDEBUG

#define yyerrok         (yyerrstatus_ = 0)
#define yyclearin       (yyla.clear ())

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYRECOVERING()  (!!yyerrstatus_)

namespace oabe {
#line 172 "zparser.tab.cc"

  /// Build a parser object.
  Parser::Parser (class Driver& driver_yyarg)
#if OABEDEBUG
    : yydebug_ (false),
      yycdebug_ (&std::cerr),
#else
    :
#endif
      driver (driver_yyarg)
  {}

  Parser::~Parser ()
  {}

  Parser::syntax_error::~syntax_error () YY_NOEXCEPT YY_NOTHROW
  {}

  /*---------.
  | symbol.  |
  `---------*/

  // basic_symbol.
  template <typename Base>
  Parser::basic_symbol<Base>::basic_symbol (const basic_symbol& that)
    : Base (that)
    , value (that.value)
    , location (that.location)
  {}


  /// Constructor for valueless symbols.
  template <typename Base>
  Parser::basic_symbol<Base>::basic_symbol (typename Base::kind_type t, YY_MOVE_REF (location_type) l)
    : Base (t)
    , value ()
    , location (l)
  {}

  template <typename Base>
  Parser::basic_symbol<Base>::basic_symbol (typename Base::kind_type t, YY_RVREF (value_type) v, YY_RVREF (location_type) l)
    : Base (t)
    , value (YY_MOVE (v))
    , location (YY_MOVE (l))
  {}


  template <typename Base>
  Parser::symbol_kind_type
  Parser::basic_symbol<Base>::type_get () const YY_NOEXCEPT
  {
    return this->kind ();
  }


  template <typename Base>
  bool
  Parser::basic_symbol<Base>::empty () const YY_NOEXCEPT
  {
    return this->kind () == symbol_kind::S_YYEMPTY;
  }

  template <typename Base>
  void
  Parser::basic_symbol<Base>::move (basic_symbol& s)
  {
    super_type::move (s);
    value = YY_MOVE (s.value);
    location = YY_MOVE (s.location);
  }

  // by_kind.
  Parser::by_kind::by_kind () YY_NOEXCEPT
    : kind_ (symbol_kind::S_YYEMPTY)
  {}

#if 201103L <= YY_CPLUSPLUS
  Parser::by_kind::by_kind (by_kind&& that) YY_NOEXCEPT
    : kind_ (that.kind_)
  {
    that.clear ();
  }
#endif

  Parser::by_kind::by_kind (const by_kind& that) YY_NOEXCEPT
    : kind_ (that.kind_)
  {}

  Parser::by_kind::by_kind (token_kind_type t) YY_NOEXCEPT
    : kind_ (yytranslate_ (t))
  {}



  void
  Parser::by_kind::clear () YY_NOEXCEPT
  {
    kind_ = symbol_kind::S_YYEMPTY;
  }

  void
  Parser::by_kind::move (by_kind& that)
  {
    kind_ = that.kind_;
    that.clear ();
  }

  Parser::symbol_kind_type
  Parser::by_kind::kind () const YY_NOEXCEPT
  {
    return kind_;
  }


  Parser::symbol_kind_type
  Parser::by_kind::type_get () const YY_NOEXCEPT
  {
    return this->kind ();
  }



  // by_state.
  Parser::by_state::by_state () YY_NOEXCEPT
    : state (empty_state)
  {}

  Parser::by_state::by_state (const by_state& that) YY_NOEXCEPT
    : state (that.state)
  {}

  void
  Parser::by_state::clear () YY_NOEXCEPT
  {
    state = empty_state;
  }

  void
  Parser::by_state::move (by_state& that)
  {
    state = that.state;
    that.clear ();
  }

  Parser::by_state::by_state (state_type s) YY_NOEXCEPT
    : state (s)
  {}

  Parser::symbol_kind_type
  Parser::by_state::kind () const YY_NOEXCEPT
  {
    if (state == empty_state)
      return symbol_kind::S_YYEMPTY;
    else
      return YY_CAST (symbol_kind_type, yystos_[+state]);
  }

  Parser::stack_symbol_type::stack_symbol_type ()
  {}

  Parser::stack_symbol_type::stack_symbol_type (YY_RVREF (stack_symbol_type) that)
    : super_type (YY_MOVE (that.state), YY_MOVE (that.value), YY_MOVE (that.location))
  {
#if 201103L <= YY_CPLUSPLUS
    // that is emptied.
    that.state = empty_state;
#endif
  }

  Parser::stack_symbol_type::stack_symbol_type (state_type s, YY_MOVE_REF (symbol_type) that)
    : super_type (s, YY_MOVE (that.value), YY_MOVE (that.location))
  {
    // that is emptied.
    that.kind_ = symbol_kind::S_YYEMPTY;
  }

#if YY_CPLUSPLUS < 201103L
  Parser::stack_symbol_type&
  Parser::stack_symbol_type::operator= (const stack_symbol_type& that)
  {
    state = that.state;
    value = that.value;
    location = that.location;
    return *this;
  }

  Parser::stack_symbol_type&
  Parser::stack_symbol_type::operator= (stack_symbol_type& that)
  {
    state = that.state;
    value = that.value;
    location = that.location;
    // that is emptied.
    that.state = empty_state;
    return *this;
  }
#endif

  template <typename Base>
  void
  Parser::yy_destroy_ (const char* yymsg, basic_symbol<Base>& yysym) const
  {
    if (yymsg)
      YY_SYMBOL_PRINT (yymsg, yysym);

    // User destructor.
    switch (yysym.kind ())
    {
      case symbol_kind::S_LEAF: // "string"
#line 89 "zparser.yy"
                    { delete (yysym.value.stringVal); }
#line 384 "zparser.tab.cc"
        break;

      case symbol_kind::S_number: // number
#line 92 "zparser.yy"
                    { delete (yysym.value.uInteger); }
#line 390 "zparser.tab.cc"
        break;

      case symbol_kind::S_policy: // policy
#line 90 "zparser.yy"
                    { delete (yysym.value.treeNode); }
#line 396 "zparser.tab.cc"
        break;

      case symbol_kind::S_attrlist: // attrlist
#line 91 "zparser.yy"
                    { delete (yysym.value.oabeAttrList); }
#line 402 "zparser.tab.cc"
        break;

      default:
        break;
    }
  }

#if OABEDEBUG
  template <typename Base>
  void
  Parser::yy_print_ (std::ostream& yyo, const basic_symbol<Base>& yysym) const
  {
    std::ostream& yyoutput = yyo;
    YY_USE (yyoutput);
    if (yysym.empty ())
      yyo << "empty symbol";
    else
      {
        symbol_kind_type yykind = yysym.kind ();
        yyo << (yykind < YYNTOKENS ? "token" : "nterm")
            << ' ' << yysym.name () << " ("
            << yysym.location << ": ";
        YY_USE (yykind);
        yyo << ')';
      }
  }
#endif

  void
  Parser::yypush_ (const char* m, YY_MOVE_REF (stack_symbol_type) sym)
  {
    if (m)
      YY_SYMBOL_PRINT (m, sym);
    yystack_.push (YY_MOVE (sym));
  }

  void
  Parser::yypush_ (const char* m, state_type s, YY_MOVE_REF (symbol_type) sym)
  {
#if 201103L <= YY_CPLUSPLUS
    yypush_ (m, stack_symbol_type (s, std::move (sym)));
#else
    stack_symbol_type ss (s, sym);
    yypush_ (m, ss);
#endif
  }

  void
  Parser::yypop_ (int n) YY_NOEXCEPT
  {
    yystack_.pop (n);
  }

#if OABEDEBUG
  std::ostream&
  Parser::debug_stream () const
  {
    return *yycdebug_;
  }

  void
  Parser::set_debug_stream (std::ostream& o)
  {
    yycdebug_ = &o;
  }


  Parser::debug_level_type
  Parser::debug_level () const
  {
    return yydebug_;
  }

  void
  Parser::set_debug_level (debug_level_type l)
  {
    yydebug_ = l;
  }
#endif // OABEDEBUG

  Parser::state_type
  Parser::yy_lr_goto_state_ (state_type yystate, int yysym)
  {
    int yyr = yypgoto_[yysym - YYNTOKENS] + yystate;
    if (0 <= yyr && yyr <= yylast_ && yycheck_[yyr] == yystate)
      return yytable_[yyr];
    else
      return yydefgoto_[yysym - YYNTOKENS];
  }

  bool
  Parser::yy_pact_value_is_default_ (int yyvalue) YY_NOEXCEPT
  {
    return yyvalue == yypact_ninf_;
  }

  bool
  Parser::yy_table_value_is_error_ (int yyvalue) YY_NOEXCEPT
  {
    return yyvalue == yytable_ninf_;
  }

  int
  Parser::operator() ()
  {
    return parse ();
  }

  int
  Parser::parse ()
  {
    int yyn;
    /// Length of the RHS of the rule being reduced.
    int yylen = 0;

    // Error handling.
    int yynerrs_ = 0;
    int yyerrstatus_ = 0;

    /// The lookahead symbol.
    symbol_type yyla;

    /// The locations where the error started and ended.
    stack_symbol_type yyerror_range[3];

    /// The return value of parse ().
    int yyresult;

#if YY_EXCEPTIONS
    try
#endif // YY_EXCEPTIONS
      {
    YYCDEBUG << "Starting parse\n";


    // User initialization code.
#line 47 "zparser.yy"
{
    // initialize the initial location object
    yyla.location.begin.filename = yyla.location.end.filename = &driver.streamname;
}

#line 545 "zparser.tab.cc"


    /* Initialize the stack.  The initial state will be set in
       yynewstate, since the latter expects the semantical and the
       location values to have been already stored, initialize these
       stacks with a primary value.  */
    yystack_.clear ();
    yypush_ (YY_NULLPTR, 0, YY_MOVE (yyla));

  /*-----------------------------------------------.
  | yynewstate -- push a new symbol on the stack.  |
  `-----------------------------------------------*/
  yynewstate:
    YYCDEBUG << "Entering state " << int (yystack_[0].state) << '\n';
    YY_STACK_PRINT ();

    // Accept?
    if (yystack_[0].state == yyfinal_)
      YYACCEPT;

    goto yybackup;


  /*-----------.
  | yybackup.  |
  `-----------*/
  yybackup:
    // Try to take a decision without lookahead.
    yyn = yypact_[+yystack_[0].state];
    if (yy_pact_value_is_default_ (yyn))
      goto yydefault;

    // Read a lookahead token.
    if (yyla.empty ())
      {
        YYCDEBUG << "Reading a token\n";
#if YY_EXCEPTIONS
        try
#endif // YY_EXCEPTIONS
          {
            yyla.kind_ = yytranslate_ (yylex (&yyla.value, &yyla.location));
          }
#if YY_EXCEPTIONS
        catch (const syntax_error& yyexc)
          {
            YYCDEBUG << "Caught exception: " << yyexc.what() << '\n';
            error (yyexc);
            goto yyerrlab1;
          }
#endif // YY_EXCEPTIONS
      }
    YY_SYMBOL_PRINT ("Next token is", yyla);

    if (yyla.kind () == symbol_kind::S_YYerror)
    {
      // The scanner already issued an error message, process directly
      // to error recovery.  But do not keep the error token as
      // lookahead, it is too special and may lead us to an endless
      // loop in error recovery. */
      yyla.kind_ = symbol_kind::S_YYUNDEF;
      goto yyerrlab1;
    }

    /* If the proper action on seeing token YYLA.TYPE is to reduce or
       to detect an error, take that action.  */
    yyn += yyla.kind ();
    if (yyn < 0 || yylast_ < yyn || yycheck_[yyn] != yyla.kind ())
      {
        goto yydefault;
      }

    // Reduce or error.
    yyn = yytable_[yyn];
    if (yyn <= 0)
      {
        if (yy_table_value_is_error_ (yyn))
          goto yyerrlab;
        yyn = -yyn;
        goto yyreduce;
      }

    // Count tokens shifted since error; after three, turn off error status.
    if (yyerrstatus_)
      --yyerrstatus_;

    // Shift the lookahead token.
    yypush_ ("Shifting", state_type (yyn), YY_MOVE (yyla));
    goto yynewstate;


  /*-----------------------------------------------------------.
  | yydefault -- do the default action for the current state.  |
  `-----------------------------------------------------------*/
  yydefault:
    yyn = yydefact_[+yystack_[0].state];
    if (yyn == 0)
      goto yyerrlab;
    goto yyreduce;


  /*-----------------------------.
  | yyreduce -- do a reduction.  |
  `-----------------------------*/
  yyreduce:
    yylen = yyr2_[yyn];
    {
      stack_symbol_type yylhs;
      yylhs.state = yy_lr_goto_state_ (yystack_[yylen].state, yyr1_[yyn]);
      /* If YYLEN is nonzero, implement the default value of the
         action: '$$ = $1'.  Otherwise, use the top of the stack.

         Otherwise, the following line sets YYLHS.VALUE to garbage.
         This behavior is undocumented and Bison users should not rely
         upon it.  */
      if (yylen)
        yylhs.value = yystack_[yylen - 1].value;
      else
        yylhs.value = yystack_[0].value;

      // Default location.
      {
        stack_type::slice range (yystack_, yylen);
        YYLLOC_DEFAULT (yylhs.location, range, yylen);
        yyerror_range[1].location = yylhs.location;
      }

      // Perform the reduction.
      YY_REDUCE_PRINT (yyn);
#if YY_EXCEPTIONS
      try
#endif // YY_EXCEPTIONS
        {
          switch (yyn)
            {
  case 2: // start: "[0]:" policy
#line 114 "zparser.yy"
                       { driver.set_policy((yystack_[0].value.treeNode)); }
#line 683 "zparser.tab.cc"
    break;

  case 3: // start: "[1]:" attrlist
#line 115 "zparser.yy"
                          { driver.set_attrlist((yystack_[0].value.oabeAttrList)); }
#line 689 "zparser.tab.cc"
    break;

  case 4: // number: "an integer" '#' "an integer"
#line 117 "zparser.yy"
                                {
                                   if (!oabe::checkValidBit((yystack_[2].value.uintVal), (yystack_[0].value.uintVal))) {
                                      YYERROR;
                                   } else {
                                      (yylhs.value.uInteger) = create_expint((yystack_[2].value.uintVal), (yystack_[0].value.uintVal));
                                   }
                                }
#line 701 "zparser.tab.cc"
    break;

  case 5: // number: "an integer"
#line 124 "zparser.yy"
                                { (yylhs.value.uInteger) = create_flexint((yystack_[0].value.uintVal)); }
#line 707 "zparser.tab.cc"
    break;

  case 6: // policy: "string"
#line 126 "zparser.yy"
                                { (yylhs.value.treeNode) = driver.leaf_node(*(yystack_[0].value.stringVal)); delete (yystack_[0].value.stringVal); }
#line 713 "zparser.tab.cc"
    break;

  case 7: // policy: policy OR policy
#line 127 "zparser.yy"
                                { (yylhs.value.treeNode) = driver.kof2_tree(1, (yystack_[2].value.treeNode), (yystack_[0].value.treeNode)); }
#line 719 "zparser.tab.cc"
    break;

  case 8: // policy: policy AND policy
#line 128 "zparser.yy"
                                { (yylhs.value.treeNode) = driver.kof2_tree(2, (yystack_[2].value.treeNode), (yystack_[0].value.treeNode)); }
#line 725 "zparser.tab.cc"
    break;

  case 9: // policy: "string" '<' number
#line 129 "zparser.yy"
                                { (yylhs.value.treeNode) = driver.lt_policy(*(yystack_[2].value.stringVal), (yystack_[0].value.uInteger)); delete (yystack_[2].value.stringVal); delete (yystack_[0].value.uInteger); }
#line 731 "zparser.tab.cc"
    break;

  case 10: // policy: "string" '>' number
#line 130 "zparser.yy"
                                { (yylhs.value.treeNode) = driver.gt_policy(*(yystack_[2].value.stringVal), (yystack_[0].value.uInteger)); delete (yystack_[2].value.stringVal); delete (yystack_[0].value.uInteger); }
#line 737 "zparser.tab.cc"
    break;

  case 11: // policy: "string" "<=" number
#line 131 "zparser.yy"
                                { (yylhs.value.treeNode) = driver.le_policy(*(yystack_[2].value.stringVal), (yystack_[0].value.uInteger)); delete (yystack_[2].value.stringVal); delete (yystack_[0].value.uInteger); }
#line 743 "zparser.tab.cc"
    break;

  case 12: // policy: "string" ">=" number
#line 132 "zparser.yy"
                                { (yylhs.value.treeNode) = driver.ge_policy(*(yystack_[2].value.stringVal), (yystack_[0].value.uInteger)); delete (yystack_[2].value.stringVal); delete (yystack_[0].value.uInteger); }
#line 749 "zparser.tab.cc"
    break;

  case 13: // policy: "string" "==" number
#line 133 "zparser.yy"
                                { (yylhs.value.treeNode) = driver.eq_policy(*(yystack_[2].value.stringVal), (yystack_[0].value.uInteger)); delete (yystack_[2].value.stringVal); delete (yystack_[0].value.uInteger); }
#line 755 "zparser.tab.cc"
    break;

  case 14: // policy: '(' policy ')'
#line 134 "zparser.yy"
                                { (yylhs.value.treeNode) = (yystack_[1].value.treeNode); }
#line 761 "zparser.tab.cc"
    break;

  case 15: // policy: "string" "in" '(' number '-' number ')'
#line 137 "zparser.yy"
                { (yylhs.value.treeNode) = driver.range_policy(*(yystack_[6].value.stringVal), (yystack_[3].value.uInteger), (yystack_[1].value.uInteger)); 
                  delete (yystack_[6].value.stringVal); delete (yystack_[3].value.uInteger); delete (yystack_[1].value.uInteger); 
                }
#line 769 "zparser.tab.cc"
    break;

  case 16: // policy: "string" "in" '{' number '-' number '}'
#line 141 "zparser.yy"
                { (yylhs.value.treeNode) = driver.range_incl_policy(*(yystack_[6].value.stringVal), (yystack_[3].value.uInteger), (yystack_[1].value.uInteger)); 
                  delete (yystack_[6].value.stringVal); delete (yystack_[3].value.uInteger); delete (yystack_[1].value.uInteger); 
                }
#line 777 "zparser.tab.cc"
    break;

  case 17: // policy: "string" '=' "string" number ',' number
#line 146 "zparser.yy"
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*(yystack_[3].value.stringVal))); 
                  (yylhs.value.treeNode) = driver.set_date_in_policy(*(yystack_[5].value.stringVal), month.get(), (yystack_[2].value.uInteger), (yystack_[0].value.uInteger)); 
                  delete (yystack_[5].value.stringVal); delete (yystack_[3].value.stringVal); delete (yystack_[2].value.uInteger); delete (yystack_[0].value.uInteger);
                }
#line 786 "zparser.tab.cc"
    break;

  case 18: // policy: "string" '=' "string" number '-' number ',' number
#line 151 "zparser.yy"
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*(yystack_[5].value.stringVal))); 
                  (yylhs.value.treeNode) = driver.range_date_in_policy(*(yystack_[7].value.stringVal), month.get(), (yystack_[4].value.uInteger), (yystack_[2].value.uInteger), (yystack_[0].value.uInteger)); 
                  delete (yystack_[7].value.stringVal); delete (yystack_[5].value.stringVal); delete (yystack_[4].value.uInteger); delete (yystack_[2].value.uInteger); delete (yystack_[0].value.uInteger);
                }
#line 795 "zparser.tab.cc"
    break;

  case 19: // policy: "string" '>' "string" number ',' number
#line 156 "zparser.yy"
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*(yystack_[3].value.stringVal))); 
                  (yylhs.value.treeNode) = driver.gt_date_in_policy(*(yystack_[5].value.stringVal), month.get(), (yystack_[2].value.uInteger), (yystack_[0].value.uInteger)); 
                  delete (yystack_[5].value.stringVal); delete (yystack_[3].value.stringVal); delete (yystack_[2].value.uInteger); delete (yystack_[0].value.uInteger);
                }
#line 804 "zparser.tab.cc"
    break;

  case 20: // policy: "string" '<' "string" number ',' number
#line 161 "zparser.yy"
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*(yystack_[3].value.stringVal))); 
                  (yylhs.value.treeNode) = driver.lt_date_in_policy(*(yystack_[5].value.stringVal), month.get(), (yystack_[2].value.uInteger), (yystack_[0].value.uInteger)); 
                  delete (yystack_[5].value.stringVal); delete (yystack_[3].value.stringVal); delete (yystack_[2].value.uInteger); delete (yystack_[0].value.uInteger);
                }
#line 813 "zparser.tab.cc"
    break;

  case 21: // policy: "string" ">=" "string" number ',' number
#line 166 "zparser.yy"
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*(yystack_[3].value.stringVal))); 
                  (yylhs.value.treeNode) = driver.ge_date_in_policy(*(yystack_[5].value.stringVal), month.get(), (yystack_[2].value.uInteger), (yystack_[0].value.uInteger)); 
                  delete (yystack_[5].value.stringVal); delete (yystack_[3].value.stringVal); delete (yystack_[2].value.uInteger); delete (yystack_[0].value.uInteger);
                }
#line 822 "zparser.tab.cc"
    break;

  case 22: // policy: "string" "<=" "string" number ',' number
#line 171 "zparser.yy"
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*(yystack_[3].value.stringVal))); 
                  (yylhs.value.treeNode) = driver.le_date_in_policy(*(yystack_[5].value.stringVal), month.get(), (yystack_[2].value.uInteger), (yystack_[0].value.uInteger)); 
                  delete (yystack_[5].value.stringVal); delete (yystack_[3].value.stringVal); delete (yystack_[2].value.uInteger); delete (yystack_[0].value.uInteger);
                }
#line 831 "zparser.tab.cc"
    break;

  case 23: // attrlist: "string"
#line 176 "zparser.yy"
                                { (yylhs.value.oabeAttrList) = driver.leaf_attr(*(yystack_[0].value.stringVal)); delete (yystack_[0].value.stringVal); }
#line 837 "zparser.tab.cc"
    break;

  case 24: // attrlist: '|' attrlist
#line 177 "zparser.yy"
                                { (yylhs.value.oabeAttrList) = driver.concat_attr((yystack_[0].value.oabeAttrList), nullptr); }
#line 843 "zparser.tab.cc"
    break;

  case 25: // attrlist: attrlist '|'
#line 178 "zparser.yy"
                                { (yylhs.value.oabeAttrList) = driver.concat_attr((yystack_[1].value.oabeAttrList), nullptr); }
#line 849 "zparser.tab.cc"
    break;

  case 26: // attrlist: attrlist '|' attrlist
#line 179 "zparser.yy"
                                { (yylhs.value.oabeAttrList) = driver.concat_attr((yystack_[2].value.oabeAttrList), (yystack_[0].value.oabeAttrList)); delete (yystack_[0].value.oabeAttrList); }
#line 855 "zparser.tab.cc"
    break;

  case 27: // attrlist: "string" '=' number
#line 180 "zparser.yy"
                                { (yylhs.value.oabeAttrList) = driver.attr_num(*(yystack_[2].value.stringVal), (yystack_[0].value.uInteger)); delete (yystack_[2].value.stringVal); delete (yystack_[0].value.uInteger); }
#line 861 "zparser.tab.cc"
    break;

  case 28: // attrlist: "string" '=' "string" number ',' number
#line 182 "zparser.yy"
                { std::unique_ptr<OpenABEUInteger> month(oabe::get_month(*(yystack_[3].value.stringVal))); 
                  (yylhs.value.oabeAttrList) = driver.set_date_in_attrlist(*(yystack_[5].value.stringVal), *(yystack_[3].value.stringVal), month.get(), (yystack_[2].value.uInteger), (yystack_[0].value.uInteger)); 
                  delete (yystack_[5].value.stringVal); delete (yystack_[3].value.stringVal); delete (yystack_[2].value.uInteger); delete (yystack_[0].value.uInteger);
                }
#line 870 "zparser.tab.cc"
    break;


#line 874 "zparser.tab.cc"

            default:
              break;
            }
        }
#if YY_EXCEPTIONS
      catch (const syntax_error& yyexc)
        {
          YYCDEBUG << "Caught exception: " << yyexc.what() << '\n';
          error (yyexc);
          YYERROR;
        }
#endif // YY_EXCEPTIONS
      YY_SYMBOL_PRINT ("-> $$ =", yylhs);
      yypop_ (yylen);
      yylen = 0;

      // Shift the result of the reduction.
      yypush_ (YY_NULLPTR, YY_MOVE (yylhs));
    }
    goto yynewstate;


  /*--------------------------------------.
  | yyerrlab -- here on detecting error.  |
  `--------------------------------------*/
  yyerrlab:
    // If not already recovering from an error, report this error.
    if (!yyerrstatus_)
      {
        ++yynerrs_;
        context yyctx (*this, yyla);
        std::string msg = yysyntax_error_ (yyctx);
        error (yyla.location, YY_MOVE (msg));
      }


    yyerror_range[1].location = yyla.location;
    if (yyerrstatus_ == 3)
      {
        /* If just tried and failed to reuse lookahead token after an
           error, discard it.  */

        // Return failure if at end of input.
        if (yyla.kind () == symbol_kind::S_YYEOF)
          YYABORT;
        else if (!yyla.empty ())
          {
            yy_destroy_ ("Error: discarding", yyla);
            yyla.clear ();
          }
      }

    // Else will try to reuse lookahead token after shifting the error token.
    goto yyerrlab1;


  /*---------------------------------------------------.
  | yyerrorlab -- error raised explicitly by YYERROR.  |
  `---------------------------------------------------*/
  yyerrorlab:
    /* Pacify compilers when the user code never invokes YYERROR and
       the label yyerrorlab therefore never appears in user code.  */
    if (false)
      YYERROR;

    /* Do not reclaim the symbols of the rule whose action triggered
       this YYERROR.  */
    yypop_ (yylen);
    yylen = 0;
    YY_STACK_PRINT ();
    goto yyerrlab1;


  /*-------------------------------------------------------------.
  | yyerrlab1 -- common code for both syntax error and YYERROR.  |
  `-------------------------------------------------------------*/
  yyerrlab1:
    yyerrstatus_ = 3;   // Each real token shifted decrements this.
    // Pop stack until we find a state that shifts the error token.
    for (;;)
      {
        yyn = yypact_[+yystack_[0].state];
        if (!yy_pact_value_is_default_ (yyn))
          {
            yyn += symbol_kind::S_YYerror;
            if (0 <= yyn && yyn <= yylast_
                && yycheck_[yyn] == symbol_kind::S_YYerror)
              {
                yyn = yytable_[yyn];
                if (0 < yyn)
                  break;
              }
          }

        // Pop the current state because it cannot handle the error token.
        if (yystack_.size () == 1)
          YYABORT;

        yyerror_range[1].location = yystack_[0].location;
        yy_destroy_ ("Error: popping", yystack_[0]);
        yypop_ ();
        YY_STACK_PRINT ();
      }
    {
      stack_symbol_type error_token;

      yyerror_range[2].location = yyla.location;
      YYLLOC_DEFAULT (error_token.location, yyerror_range, 2);

      // Shift the error token.
      error_token.state = state_type (yyn);
      yypush_ ("Shifting", YY_MOVE (error_token));
    }
    goto yynewstate;


  /*-------------------------------------.
  | yyacceptlab -- YYACCEPT comes here.  |
  `-------------------------------------*/
  yyacceptlab:
    yyresult = 0;
    goto yyreturn;


  /*-----------------------------------.
  | yyabortlab -- YYABORT comes here.  |
  `-----------------------------------*/
  yyabortlab:
    yyresult = 1;
    goto yyreturn;


  /*-----------------------------------------------------.
  | yyreturn -- parsing is finished, return the result.  |
  `-----------------------------------------------------*/
  yyreturn:
    if (!yyla.empty ())
      yy_destroy_ ("Cleanup: discarding lookahead", yyla);

    /* Do not reclaim the symbols of the rule whose action triggered
       this YYABORT or YYACCEPT.  */
    yypop_ (yylen);
    YY_STACK_PRINT ();
    while (1 < yystack_.size ())
      {
        yy_destroy_ ("Cleanup: popping", yystack_[0]);
        yypop_ ();
      }

    return yyresult;
  }
#if YY_EXCEPTIONS
    catch (...)
      {
        YYCDEBUG << "Exception caught: cleaning lookahead and stack\n";
        // Do not try to display the values of the reclaimed symbols,
        // as their printers might throw an exception.
        if (!yyla.empty ())
          yy_destroy_ (YY_NULLPTR, yyla);

        while (1 < yystack_.size ())
          {
            yy_destroy_ (YY_NULLPTR, yystack_[0]);
            yypop_ ();
          }
        throw;
      }
#endif // YY_EXCEPTIONS
  }

  void
  Parser::error (const syntax_error& yyexc)
  {
    error (yyexc.location, yyexc.what ());
  }

  /* Return YYSTR after stripping away unnecessary quotes and
     backslashes, so that it's suitable for yyerror.  The heuristic is
     that double-quoting is unnecessary unless the string contains an
     apostrophe, a comma, or backslash (other than backslash-backslash).
     YYSTR is taken from yytname.  */
  std::string
  Parser::yytnamerr_ (const char *yystr)
  {
    if (*yystr == '"')
      {
        std::string yyr;
        char const *yyp = yystr;

        for (;;)
          switch (*++yyp)
            {
            case '\'':
            case ',':
              goto do_not_strip_quotes;

            case '\\':
              if (*++yyp != '\\')
                goto do_not_strip_quotes;
              else
                goto append;

            append:
            default:
              yyr += *yyp;
              break;

            case '"':
              return yyr;
            }
      do_not_strip_quotes: ;
      }

    return yystr;
  }

  std::string
  Parser::symbol_name (symbol_kind_type yysymbol)
  {
    return yytnamerr_ (yytname_[yysymbol]);
  }



  // Parser::context.
  Parser::context::context (const Parser& yyparser, const symbol_type& yyla)
    : yyparser_ (yyparser)
    , yyla_ (yyla)
  {}

  int
  Parser::context::expected_tokens (symbol_kind_type yyarg[], int yyargn) const
  {
    // Actual number of expected tokens
    int yycount = 0;

    const int yyn = yypact_[+yyparser_.yystack_[0].state];
    if (!yy_pact_value_is_default_ (yyn))
      {
        /* Start YYX at -YYN if negative to avoid negative indexes in
           YYCHECK.  In other words, skip the first -YYN actions for
           this state because they are default actions.  */
        const int yyxbegin = yyn < 0 ? -yyn : 0;
        // Stay within bounds of both yycheck and yytname.
        const int yychecklim = yylast_ - yyn + 1;
        const int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
        for (int yyx = yyxbegin; yyx < yyxend; ++yyx)
          if (yycheck_[yyx + yyn] == yyx && yyx != symbol_kind::S_YYerror
              && !yy_table_value_is_error_ (yytable_[yyx + yyn]))
            {
              if (!yyarg)
                ++yycount;
              else if (yycount == yyargn)
                return 0;
              else
                yyarg[yycount++] = YY_CAST (symbol_kind_type, yyx);
            }
      }

    if (yyarg && yycount == 0 && 0 < yyargn)
      yyarg[0] = symbol_kind::S_YYEMPTY;
    return yycount;
  }






  int
  Parser::yy_syntax_error_arguments_ (const context& yyctx,
                                                 symbol_kind_type yyarg[], int yyargn) const
  {
    /* There are many possibilities here to consider:
       - If this state is a consistent state with a default action, then
         the only way this function was invoked is if the default action
         is an error action.  In that case, don't check for expected
         tokens because there are none.
       - The only way there can be no lookahead present (in yyla) is
         if this state is a consistent state with a default action.
         Thus, detecting the absence of a lookahead is sufficient to
         determine that there is no unexpected or expected token to
         report.  In that case, just report a simple "syntax error".
       - Don't assume there isn't a lookahead just because this state is
         a consistent state with a default action.  There might have
         been a previous inconsistent state, consistent state with a
         non-default action, or user semantic action that manipulated
         yyla.  (However, yyla is currently not documented for users.)
       - Of course, the expected token list depends on states to have
         correct lookahead information, and it depends on the parser not
         to perform extra reductions after fetching a lookahead from the
         scanner and before detecting a syntax error.  Thus, state merging
         (from LALR or IELR) and default reductions corrupt the expected
         token list.  However, the list is correct for canonical LR with
         one exception: it will still contain any token that will not be
         accepted due to an error action in a later state.
    */

    if (!yyctx.lookahead ().empty ())
      {
        if (yyarg)
          yyarg[0] = yyctx.token ();
        int yyn = yyctx.expected_tokens (yyarg ? yyarg + 1 : yyarg, yyargn - 1);
        return yyn + 1;
      }
    return 0;
  }

  // Generate an error message.
  std::string
  Parser::yysyntax_error_ (const context& yyctx) const
  {
    // Its maximum.
    enum { YYARGS_MAX = 5 };
    // Arguments of yyformat.
    symbol_kind_type yyarg[YYARGS_MAX];
    int yycount = yy_syntax_error_arguments_ (yyctx, yyarg, YYARGS_MAX);

    char const* yyformat = YY_NULLPTR;
    switch (yycount)
      {
#define YYCASE_(N, S)                         \
        case N:                               \
          yyformat = S;                       \
        break
      default: // Avoid compiler warnings.
        YYCASE_ (0, YY_("syntax error"));
        YYCASE_ (1, YY_("syntax error, unexpected %s"));
        YYCASE_ (2, YY_("syntax error, unexpected %s, expecting %s"));
        YYCASE_ (3, YY_("syntax error, unexpected %s, expecting %s or %s"));
        YYCASE_ (4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
        YYCASE_ (5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
      }

    std::string yyres;
    // Argument number.
    std::ptrdiff_t yyi = 0;
    for (char const* yyp = yyformat; *yyp; ++yyp)
      if (yyp[0] == '%' && yyp[1] == 's' && yyi < yycount)
        {
          yyres += symbol_name (yyarg[yyi++]);
          ++yyp;
        }
      else
        yyres += *yyp;
    return yyres;
  }


  const signed char Parser::yypact_ninf_ = -20;

  const signed char Parser::yytable_ninf_ = -1;

  const signed char
  Parser::yypact_[] =
  {
      17,    -2,     1,     7,    11,    -2,    44,   -13,     1,    -1,
     -20,    12,    51,    53,   -15,    55,    58,    34,     3,    -2,
      -2,    60,    -1,     1,    20,   -20,    12,   -20,    12,   -20,
      12,    12,    12,   -20,    12,   -20,    12,   -20,    56,   -20,
      12,   -20,    -1,    62,    39,    40,    45,    46,    43,    47,
     -19,    48,   -20,    12,    12,    12,    12,    12,    12,    12,
      12,    12,   -20,   -20,    49,    52,   -20,   -20,    54,   -20,
     -20,   -20,   -20,    12,   -20
  };

  const signed char
  Parser::yydefact_[] =
  {
       0,     0,     0,     0,     6,     0,     2,    23,     0,     3,
       1,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    24,    25,     5,    13,     0,    11,     0,    12,
       0,     0,     0,     9,     0,    10,     0,    14,     7,     8,
       0,    27,    26,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     4,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    22,    21,     0,     0,    20,    19,     0,    17,
      28,    15,    16,     0,    18
  };

  const signed char
  Parser::yypgoto_[] =
  {
     -20,   -20,   -12,    31,    29
  };

  const signed char
  Parser::yydefgoto_[] =
  {
       0,     3,    25,     6,     9
  };

  const signed char
  Parser::yytable_[] =
  {
      27,    29,     4,    33,    35,     7,    59,    10,    30,    41,
      60,    31,    19,    20,    44,    21,    45,    24,    46,    47,
      48,     5,    49,    11,    50,    12,    13,    37,    51,    23,
      14,     8,    15,    16,     1,     2,    18,    22,    36,    17,
      43,    62,    63,    64,    65,    66,    67,    68,    69,    70,
      38,    39,    42,    19,    20,    26,    24,    28,    24,    32,
      24,    74,    34,    24,    40,    24,    20,    52,    53,    54,
      55,    56,    57,    71,     0,     0,    58,    61,     0,    72,
       0,     0,     0,    73
  };

  const signed char
  Parser::yycheck_[] =
  {
      12,    13,     4,    15,    16,     4,    25,     0,    23,    21,
      29,    26,     9,    10,    26,    28,    28,     5,    30,    31,
      32,    23,    34,    12,    36,    14,    15,    24,    40,    30,
      19,    30,    21,    22,    17,    18,     5,     8,     4,    28,
      20,    53,    54,    55,    56,    57,    58,    59,    60,    61,
      19,    20,    23,     9,    10,     4,     5,     4,     5,     4,
       5,    73,     4,     5,     4,     5,    10,     5,    29,    29,
      25,    25,    29,    24,    -1,    -1,    29,    29,    -1,    27,
      -1,    -1,    -1,    29
  };

  const signed char
  Parser::yystos_[] =
  {
       0,    17,    18,    32,     4,    23,    34,     4,    30,    35,
       0,    12,    14,    15,    19,    21,    22,    28,    34,     9,
      10,    28,    35,    30,     5,    33,     4,    33,     4,    33,
      23,    26,     4,    33,     4,    33,     4,    24,    34,    34,
       4,    33,    35,    20,    33,    33,    33,    33,    33,    33,
      33,    33,     5,    29,    29,    25,    25,    29,    29,    25,
      29,    29,    33,    33,    33,    33,    33,    33,    33,    33,
      33,    24,    27,    29,    33
  };

  const signed char
  Parser::yyr1_[] =
  {
       0,    31,    32,    32,    33,    33,    34,    34,    34,    34,
      34,    34,    34,    34,    34,    34,    34,    34,    34,    34,
      34,    34,    34,    35,    35,    35,    35,    35,    35
  };

  const signed char
  Parser::yyr2_[] =
  {
       0,     2,     2,     2,     3,     1,     1,     3,     3,     3,
       3,     3,     3,     3,     3,     7,     7,     6,     8,     6,
       6,     6,     6,     1,     2,     2,     3,     3,     6
  };


#if OABEDEBUG || 1
  // YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
  // First, the terminals, then, starting at \a YYNTOKENS, nonterminals.
  const char*
  const Parser::yytname_[] =
  {
  "\"end of file\"", "error", "\"invalid token\"", "\"end of line\"",
  "\"string\"", "\"an integer\"", "\"OpenABEUInteger\"",
  "\"OpenABE tree node\"", "\"OpenABE attribute list\"", "OR", "AND",
  "\"of\"", "\"==\"", "\"=\"", "\"<=\"", "\">=\"", "\"error\"", "\"[0]:\"",
  "\"[1]:\"", "\"in\"", "'#'", "'<'", "'>'", "'('", "')'", "'-'", "'{'",
  "'}'", "'='", "','", "'|'", "$accept", "start", "number", "policy",
  "attrlist", YY_NULLPTR
  };
#endif


#if OABEDEBUG
  const unsigned char
  Parser::yyrline_[] =
  {
       0,   114,   114,   115,   117,   124,   126,   127,   128,   129,
     130,   131,   132,   133,   134,   136,   140,   145,   150,   155,
     160,   165,   170,   176,   177,   178,   179,   180,   181
  };

  void
  Parser::yy_stack_print_ () const
  {
    *yycdebug_ << "Stack now";
    for (stack_type::const_iterator
           i = yystack_.begin (),
           i_end = yystack_.end ();
         i != i_end; ++i)
      *yycdebug_ << ' ' << int (i->state);
    *yycdebug_ << '\n';
  }

  void
  Parser::yy_reduce_print_ (int yyrule) const
  {
    int yylno = yyrline_[yyrule];
    int yynrhs = yyr2_[yyrule];
    // Print the symbols being reduced, and their result.
    *yycdebug_ << "Reducing stack by rule " << yyrule - 1
               << " (line " << yylno << "):\n";
    // The symbols being reduced.
    for (int yyi = 0; yyi < yynrhs; yyi++)
      YY_SYMBOL_PRINT ("   $" << yyi + 1 << " =",
                       yystack_[(yynrhs) - (yyi + 1)]);
  }
#endif // OABEDEBUG

  Parser::symbol_kind_type
  Parser::yytranslate_ (int t) YY_NOEXCEPT
  {
    // YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to
    // TOKEN-NUM as returned by yylex.
    static
    const signed char
    translate_table[] =
    {
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,    20,     2,     2,     2,     2,
      23,    24,     2,     2,    29,    25,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      21,    28,    22,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    26,    30,    27,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19
    };
    // Last valid token kind.
    const int code_max = 274;

    if (t <= 0)
      return symbol_kind::S_YYEOF;
    else if (t <= code_max)
      return static_cast <symbol_kind_type> (translate_table[t]);
    else
      return symbol_kind::S_YYUNDEF;
  }

} // oabe
#line 1429 "zparser.tab.cc"

#line 192 "zparser.yy"
 /*** Additional Code ***/

void oabe::Parser::error(const Parser::location_type& l,
			    const std::string& m)
{
    driver.error(l, m);
}
