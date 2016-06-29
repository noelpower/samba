/* A Bison parser, made by GNU Bison 2.7.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2012 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_YY_WSP_AQS_PARSER_H_INCLUDED
# define YY_YY_WSP_AQS_PARSER_H_INCLUDED
/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
/* Line 2058 of yacc.c  */
#line 34 "wsp_aqs_parser.y"


#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif



/* Line 2058 of yacc.c  */
#line 56 "wsp_aqs_parser.h"

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     TOKEN_AND = 259,
     TOKEN_OR = 261,
     TOKEN_NE = 263,
     TOKEN_GE = 265,
     TOKEN_LE = 267,
     TOKEN_LT = 269,
     TOKEN_GT = 271,
     TOKEN_NOT = 273,
     TOKEN_EQ = 275,
     TOKEN_PROP_EQUALS = 277,
     TOKEN_STARTS_WITH = 279,
     TOKEN_EQUALS = 281,
     TOKEN_LPAREN = 282,
     TOKEN_RPAREN = 283,
     TOKEN_WHERE = 284,
     TOKEN_SELECT = 285,
     TOKEN_TRUE = 286,
     TOKEN_FALSE = 287,
     TOKEN_COMMA = 288,
     TOKEN_MATCHES = 289,
     TOKEN_K = 290,
     TOKEN_M = 291,
     TOKEN_G = 292,
     TOKEN_T = 293,
     TOKEN_KB = 294,
     TOKEN_MB = 295,
     TOKEN_GB = 296,
     TOKEN_TB = 297,
     TOKEN_RANGE = 298,
     TOKEN_TODAY = 299,
     TOKEN_YESTERDAY = 300,
     TOKEN_THISWEEK = 301,
     TOKEN_LASTWEEK = 302,
     TOKEN_THISMONTH = 303,
     TOKEN_LASTMONTH = 304,
     TOKEN_THISYEAR = 305,
     TOKEN_LASTYEAR = 306,
     TOKEN_EMPTY = 307,
     TOKEN_TINY = 308,
     TOKEN_SMALL = 309,
     TOKEN_MEDIUM = 310,
     TOKEN_LARGE = 311,
     TOKEN_HUGE = 312,
     TOKEN_GIGANTIC = 313,
     TOKEN_NUMBER = 314,
     TOKEN_IDENTIFIER = 315,
     TOKEN_STRING_LITERAL = 316
   };
#endif


#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{
/* Line 2058 of yacc.c  */
#line 51 "wsp_aqs_parser.y"

	char *strval;
	int64_t num;
	t_value_holder *value;
	t_select_stmt *select_stmt;
	t_select_stmt *query_stmt;
	t_basic_restr *bas_rest;
	t_basic_query *bas_query;
	t_restr *restr;
	t_query       *query;
	t_col_list *columns;
	daterange_type daterange;
	sizerange_type sizerange;
	t_optype prop_op;


/* Line 2058 of yacc.c  */
#line 137 "wsp_aqs_parser.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif


#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (t_select_stmt **select, yyscan_t scanner);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */

#endif /* !YY_YY_WSP_AQS_PARSER_H_INCLUDED  */
