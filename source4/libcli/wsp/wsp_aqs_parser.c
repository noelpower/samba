/* A Bison parser, made by GNU Bison 2.7.  */

/* Bison implementation for Yacc-like parsers in C
   
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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.7"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* Copy the first part of user declarations.  */
/* Line 371 of yacc.c  */
#line 22 "wsp_aqs_parser.y"


#include "includes.h"
#include "libcli/wsp/wsp_aqs.h"
#include "libcli/wsp/wsp_aqs_parser.h"
#include "libcli/wsp/wsp_aqs_lexer.h"

static int yyerror(t_select_stmt **stmt, yyscan_t scanner, const char *msg)
{
	fprintf(stderr,"Error :%s\n",msg); return 0;
}

/* Line 371 of yacc.c  */
#line 81 "wsp_aqs_parser.c"

# ifndef YY_NULL
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULL nullptr
#  else
#   define YY_NULL 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "wsp_aqs_parser.h".  */
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
/* Line 387 of yacc.c  */
#line 34 "wsp_aqs_parser.y"


#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif



/* Line 387 of yacc.c  */
#line 123 "wsp_aqs_parser.c"

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
/* Line 387 of yacc.c  */
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


/* Line 387 of yacc.c  */
#line 204 "wsp_aqs_parser.c"
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

/* Copy the second part of user declarations.  */

/* Line 390 of yacc.c  */
#line 231 "wsp_aqs_parser.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(N) (N)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (YYID (0))
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  15
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   107

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  62
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  16
/* YYNRULES -- Number of rules.  */
#define YYNRULES  61
/* YYNRULES -- Number of states.  */
#define YYNSTATES  81

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   316

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
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
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint8 yyprhs[] =
{
       0,     0,     3,     5,    10,    12,    14,    18,    20,    22,
      26,    30,    34,    37,    41,    43,    45,    48,    51,    55,
      57,    59,    61,    63,    65,    67,    69,    71,    73,    77,
      79,    81,    83,    85,    87,    89,    91,    93,    95,    97,
      99,   101,   103,   105,   107,   109,   111,   113,   116,   119,
     122,   125,   128,   131,   134,   137,   139,   141,   143,   145,
     147,   151
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      63,     0,    -1,    64,    -1,    30,    65,    29,    67,    -1,
      67,    -1,    66,    -1,    66,    33,    65,    -1,    60,    -1,
      68,    -1,    27,    67,    28,    -1,    67,     4,    67,    -1,
      67,     6,    67,    -1,    18,    67,    -1,    69,    22,    70,
      -1,    60,    -1,    73,    -1,    71,    73,    -1,    72,    73,
      -1,    27,    77,    28,    -1,    20,    -1,     8,    -1,    10,
      -1,    12,    -1,    14,    -1,    16,    -1,    24,    -1,    26,
      -1,    76,    -1,    76,    43,    76,    -1,    74,    -1,    75,
      -1,    44,    -1,    45,    -1,    46,    -1,    47,    -1,    48,
      -1,    49,    -1,    50,    -1,    51,    -1,    52,    -1,    53,
      -1,    54,    -1,    55,    -1,    56,    -1,    57,    -1,    58,
      -1,    59,    -1,    59,    35,    -1,    59,    36,    -1,    59,
      37,    -1,    59,    38,    -1,    59,    39,    -1,    59,    40,
      -1,    59,    41,    -1,    59,    42,    -1,    31,    -1,    32,
      -1,    61,    -1,    60,    -1,    70,    -1,    77,     4,    77,
      -1,    77,     6,    77,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   140,   140,   146,   152,   161,   167,   176,   185,   191,
     197,   203,   209,   218,   226,   235,   241,   247,   253,   265,
     266,   267,   268,   269,   270,   274,   275,   279,   280,   286,
     292,   301,   302,   303,   304,   305,   306,   307,   308,   312,
     313,   314,   315,   316,   317,   318,   322,   328,   334,   340,
     346,   353,   359,   365,   371,   378,   384,   390,   398,   406,
     412,   418
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "\"AND\"", "TOKEN_AND", "\"OR\"",
  "TOKEN_OR", "\"!=\"", "TOKEN_NE", "\">=\"", "TOKEN_GE", "\"<=\"",
  "TOKEN_LE", "\"<\"", "TOKEN_LT", "\">\"", "TOKEN_GT", "\"NOT\"",
  "TOKEN_NOT", "\"==\"", "TOKEN_EQ", "\":\"", "TOKEN_PROP_EQUALS",
  "\"$<\"", "TOKEN_STARTS_WITH", "\"$=\"", "TOKEN_EQUALS", "TOKEN_LPAREN",
  "TOKEN_RPAREN", "TOKEN_WHERE", "TOKEN_SELECT", "TOKEN_TRUE",
  "TOKEN_FALSE", "TOKEN_COMMA", "TOKEN_MATCHES", "TOKEN_K", "TOKEN_M",
  "TOKEN_G", "TOKEN_T", "TOKEN_KB", "TOKEN_MB", "TOKEN_GB", "TOKEN_TB",
  "TOKEN_RANGE", "TOKEN_TODAY", "TOKEN_YESTERDAY", "TOKEN_THISWEEK",
  "TOKEN_LASTWEEK", "TOKEN_THISMONTH", "TOKEN_LASTMONTH", "TOKEN_THISYEAR",
  "TOKEN_LASTYEAR", "TOKEN_EMPTY", "TOKEN_TINY", "TOKEN_SMALL",
  "TOKEN_MEDIUM", "TOKEN_LARGE", "TOKEN_HUGE", "TOKEN_GIGANTIC",
  "TOKEN_NUMBER", "TOKEN_IDENTIFIER", "TOKEN_STRING_LITERAL", "$accept",
  "input", "select_stmt", "cols", "col", "query", "basic_query", "prop",
  "basic_restr", "property_op", "content_op", "value", "date_shortcut",
  "size_shortcut", "simple_value", "restr", YY_NULL
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    62,    63,    64,    64,    65,    65,    66,    67,    67,
      67,    67,    67,    68,    69,    70,    70,    70,    70,    71,
      71,    71,    71,    71,    71,    72,    72,    73,    73,    73,
      73,    74,    74,    74,    74,    74,    74,    74,    74,    75,
      75,    75,    75,    75,    75,    75,    76,    76,    76,    76,
      76,    76,    76,    76,    76,    76,    76,    76,    76,    77,
      77,    77
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     4,     1,     1,     3,     1,     1,     3,
       3,     3,     2,     3,     1,     1,     2,     2,     3,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     3,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     2,     2,     2,
       2,     2,     2,     2,     2,     1,     1,     1,     1,     1,
       3,     3
};

/* YYDEFACT[STATE-NAME] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     0,     0,     0,    14,     0,     2,     4,     8,     0,
      12,     0,     7,     0,     5,     1,     0,     0,     0,     9,
       0,     0,    10,    11,    20,    21,    22,    23,    24,    19,
      25,    26,     0,    55,    56,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    58,    57,    13,     0,     0,    15,    29,    30,    27,
       3,     6,    59,     0,    47,    48,    49,    50,    51,    52,
      53,    54,    16,    17,     0,     0,     0,    18,    28,    60,
      61
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,     5,     6,    13,    14,     7,     8,     9,    62,    54,
      55,    56,    57,    58,    59,    63
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -62
static const yytype_int8 yypact[] =
{
      -5,    -1,    -1,   -55,   -62,    20,   -62,    -3,   -62,     5,
     -62,     3,   -62,     0,   -12,   -62,    -1,    -1,    -8,   -62,
      -1,   -55,    22,   -62,   -62,   -62,   -62,   -62,   -62,   -62,
     -62,   -62,    -8,   -62,   -62,   -62,   -62,   -62,   -62,   -62,
     -62,   -62,   -62,   -62,   -62,   -62,   -62,   -62,   -62,   -62,
      55,   -62,   -62,   -62,    25,    25,   -62,   -62,   -62,   -13,
      -3,   -62,   -62,    59,   -62,   -62,   -62,   -62,   -62,   -62,
     -62,   -62,   -62,   -62,     1,    -8,    -8,   -62,   -62,    28,
     -62
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -62,   -62,   -62,    14,   -62,    87,   -62,   -62,    36,   -62,
     -62,   -44,   -62,   -62,   -16,   -61
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
      24,    16,    25,    17,    26,    12,    27,    16,    28,    17,
      72,    73,    29,     1,    79,    80,    30,     1,    31,    32,
      15,    21,     2,    33,    34,     3,     2,    18,    17,    20,
      74,    19,    33,    34,    76,    61,    35,    36,    37,    38,
      39,    40,    41,    42,    43,    44,    45,    46,    47,    48,
      49,    50,    51,    52,    53,     4,    33,    34,    78,     4,
      50,    51,    52,    75,     0,    76,     0,     0,     0,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    51,    52,    77,    10,    11,
      64,    65,    66,    67,    68,    69,    70,    71,     0,     0,
       0,     0,     0,    22,    23,     0,     0,    60
};

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-62)))

#define yytable_value_is_error(Yytable_value) \
  YYID (0)

static const yytype_int8 yycheck[] =
{
       8,     4,    10,     6,    12,    60,    14,     4,    16,     6,
      54,    55,    20,    18,    75,    76,    24,    18,    26,    27,
       0,    33,    27,    31,    32,    30,    27,    22,     6,    29,
      43,    28,    31,    32,     6,    21,    44,    45,    46,    47,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    60,    61,    18,    60,    31,    32,    74,    60,
      59,    60,    61,     4,    -1,     6,    -1,    -1,    -1,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    28,     1,     2,
      35,    36,    37,    38,    39,    40,    41,    42,    -1,    -1,
      -1,    -1,    -1,    16,    17,    -1,    -1,    20
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    18,    27,    30,    60,    63,    64,    67,    68,    69,
      67,    67,    60,    65,    66,     0,     4,     6,    22,    28,
      29,    33,    67,    67,     8,    10,    12,    14,    16,    20,
      24,    26,    27,    31,    32,    44,    45,    46,    47,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    70,    71,    72,    73,    74,    75,    76,
      67,    65,    70,    77,    35,    36,    37,    38,    39,    40,
      41,    42,    73,    73,    43,     4,     6,    28,    76,    77,
      77
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  However,
   YYFAIL appears to be in use.  Nevertheless, it is formally deprecated
   in Bison 2.4.2's NEWS entry, where a plan to phase it out is
   discussed.  */

#define YYFAIL		goto yyerrlab
#if defined YYFAIL
  /* This is here to suppress warnings from the GCC cpp's
     -Wunused-macros.  Normally we don't worry about that warning, but
     some users do, and we want to make it easy for users to remove
     YYFAIL uses, which will produce warnings from Bison 2.5.  */
#endif

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (select, scanner, YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))

/* Error token number */
#define YYTERROR	1
#define YYERRCODE	256


/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */
#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval, scanner)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value, select, scanner); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, t_select_stmt **select, yyscan_t scanner)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep, select, scanner)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    t_select_stmt **select;
    yyscan_t scanner;
#endif
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
  YYUSE (select);
  YYUSE (scanner);
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
        break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, t_select_stmt **select, yyscan_t scanner)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep, select, scanner)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    t_select_stmt **select;
    yyscan_t scanner;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, select, scanner);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule, t_select_stmt **select, yyscan_t scanner)
#else
static void
yy_reduce_print (yyvsp, yyrule, select, scanner)
    YYSTYPE *yyvsp;
    int yyrule;
    t_select_stmt **select;
    yyscan_t scanner;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       , select, scanner);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule, select, scanner); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
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
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULL, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULL;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - Assume YYFAIL is not used.  It's too flawed to consider.  See
       <http://lists.gnu.org/archive/html/bison-patches/2009-12/msg00024.html>
       for details.  YYERROR is fine as it does not invoke this
       function.
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULL, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, t_select_stmt **select, yyscan_t scanner)
#else
static void
yydestruct (yymsg, yytype, yyvaluep, select, scanner)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
    t_select_stmt **select;
    yyscan_t scanner;
#endif
{
  YYUSE (yyvaluep);
  YYUSE (select);
  YYUSE (scanner);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
        break;
    }
}




/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (t_select_stmt **select, yyscan_t scanner)
#else
int
yyparse (select, scanner)
    t_select_stmt **select;
    yyscan_t scanner;
#endif
#endif
{
/* The lookahead symbol.  */
int yychar;


#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
static YYSTYPE yyval_default;
# define YY_INITIAL_VALUE(Value) = Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval YY_INITIAL_VALUE(yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
/* Line 1792 of yacc.c  */
#line 140 "wsp_aqs_parser.y"
    {
		*select = (yyvsp[(1) - (1)].select_stmt);
	}
    break;

  case 3:
/* Line 1792 of yacc.c  */
#line 146 "wsp_aqs_parser.y"
    {
		(yyval.select_stmt) = create_select(talloc_tos(), (yyvsp[(2) - (4)].columns), (yyvsp[(4) - (4)].query) );
		if (!(yyval.select_stmt)) {
			 YYERROR;
		}
	}
    break;

  case 4:
/* Line 1792 of yacc.c  */
#line 152 "wsp_aqs_parser.y"
    {
		(yyval.select_stmt) = create_select(talloc_tos(), NULL, (yyvsp[(1) - (1)].query) );
		if (!(yyval.select_stmt)) {
			 YYERROR;
		}
	}
    break;

  case 5:
/* Line 1792 of yacc.c  */
#line 161 "wsp_aqs_parser.y"
    {
		(yyval.columns) = create_cols(talloc_tos(), (yyvsp[(1) - (1)].strval), NULL);
		if (!(yyval.columns)) {
			 YYERROR;
		}
	}
    break;

  case 6:
/* Line 1792 of yacc.c  */
#line 167 "wsp_aqs_parser.y"
    {
		(yyval.columns) = create_cols(talloc_tos(), (yyvsp[(1) - (3)].strval), (yyvsp[(3) - (3)].columns));
		if (!(yyval.columns)) {
			 YYERROR;
		}
	}
    break;

  case 7:
/* Line 1792 of yacc.c  */
#line 176 "wsp_aqs_parser.y"
    {
		(yyval.strval) = (yyvsp[(1) - (1)].strval);
		if (!(yyval.strval)) {
			 YYERROR;
		}
	}
    break;

  case 8:
/* Line 1792 of yacc.c  */
#line 185 "wsp_aqs_parser.y"
    {
		(yyval.query) = create_query_node(talloc_tos(), eVALUE, NULL, NULL, (yyvsp[(1) - (1)].bas_query));
		if (!(yyval.query)) {
			 YYERROR;
		}
	}
    break;

  case 9:
/* Line 1792 of yacc.c  */
#line 191 "wsp_aqs_parser.y"
    {
		(yyval.query) = (yyvsp[(2) - (3)].query);
		if (!(yyval.query)) {
			 YYERROR;
		}
	}
    break;

  case 10:
/* Line 1792 of yacc.c  */
#line 197 "wsp_aqs_parser.y"
    {
		(yyval.query) = create_query_node(talloc_tos(), eAND, (yyvsp[(1) - (3)].query), (yyvsp[(3) - (3)].query), NULL);
		if (!(yyval.query)) {
			 YYERROR;
		}
	}
    break;

  case 11:
/* Line 1792 of yacc.c  */
#line 203 "wsp_aqs_parser.y"
    {
		(yyval.query) = create_query_node(talloc_tos(), eOR, (yyvsp[(1) - (3)].query), (yyvsp[(3) - (3)].query), NULL);
		if (!(yyval.query)) {
			 YYERROR;
		}
	}
    break;

  case 12:
/* Line 1792 of yacc.c  */
#line 209 "wsp_aqs_parser.y"
    {
		(yyval.query) = create_query_node(talloc_tos(), eNOT, NULL, (yyvsp[(2) - (2)].query), NULL);
		if (!(yyval.query)) {
			 YYERROR;
		}
	}
    break;

  case 13:
/* Line 1792 of yacc.c  */
#line 218 "wsp_aqs_parser.y"
    {
		(yyval.bas_query) = create_basic_query(talloc_tos(), (yyvsp[(1) - (3)].strval), (yyvsp[(3) - (3)].bas_rest));
		if (!(yyval.bas_query)) {
			 YYERROR;
		}
	}
    break;

  case 14:
/* Line 1792 of yacc.c  */
#line 226 "wsp_aqs_parser.y"
    {
		(yyval.strval) = (yyvsp[(1) - (1)].strval);
		if (!(yyval.strval)) {
			 YYERROR;
		}
	}
    break;

  case 15:
/* Line 1792 of yacc.c  */
#line 235 "wsp_aqs_parser.y"
    {
		(yyval.bas_rest) = create_basic_restr(talloc_tos(), RTPROPERTY, eEQ, (yyvsp[(1) - (1)].value));
		if (!(yyval.bas_rest)) {
			 YYERROR;
		}
	}
    break;

  case 16:
/* Line 1792 of yacc.c  */
#line 241 "wsp_aqs_parser.y"
    {
		(yyval.bas_rest) = create_basic_restr(talloc_tos(), RTPROPERTY, (yyvsp[(1) - (2)].prop_op), (yyvsp[(2) - (2)].value));
		if (!(yyval.bas_rest)) {
			 YYERROR;
		}
	}
    break;

  case 17:
/* Line 1792 of yacc.c  */
#line 247 "wsp_aqs_parser.y"
    {
		(yyval.bas_rest) = create_basic_restr(talloc_tos(), RTCONTENT, (yyvsp[(1) - (2)].prop_op), (yyvsp[(2) - (2)].value));
		if (!(yyval.bas_rest)) {
			 YYERROR;
		}
	}
    break;

  case 18:
/* Line 1792 of yacc.c  */
#line 253 "wsp_aqs_parser.y"
    {
		t_value_holder *holder = talloc_zero(talloc_tos(), t_value_holder);
		holder->type = RESTR;
		holder->value.restr_tree = (yyvsp[(2) - (3)].restr);
		(yyval.bas_rest) = create_basic_restr(talloc_tos(), RTNONE, eEQ, holder);
		if (!(yyval.bas_rest)) {
			 YYERROR;
		}
	}
    break;

  case 19:
/* Line 1792 of yacc.c  */
#line 265 "wsp_aqs_parser.y"
    { (yyval.prop_op) = eEQ; }
    break;

  case 20:
/* Line 1792 of yacc.c  */
#line 266 "wsp_aqs_parser.y"
    { (yyval.prop_op) = eNE; }
    break;

  case 21:
/* Line 1792 of yacc.c  */
#line 267 "wsp_aqs_parser.y"
    { (yyval.prop_op) = eGE; }
    break;

  case 22:
/* Line 1792 of yacc.c  */
#line 268 "wsp_aqs_parser.y"
    { (yyval.prop_op) = eLE; }
    break;

  case 23:
/* Line 1792 of yacc.c  */
#line 269 "wsp_aqs_parser.y"
    { (yyval.prop_op) = eLT; }
    break;

  case 24:
/* Line 1792 of yacc.c  */
#line 270 "wsp_aqs_parser.y"
    { (yyval.prop_op) = eGT; }
    break;

  case 25:
/* Line 1792 of yacc.c  */
#line 274 "wsp_aqs_parser.y"
    { (yyval.prop_op) = eSTARTSWITH; }
    break;

  case 26:
/* Line 1792 of yacc.c  */
#line 275 "wsp_aqs_parser.y"
    { (yyval.prop_op) = eEQUALS; }
    break;

  case 27:
/* Line 1792 of yacc.c  */
#line 279 "wsp_aqs_parser.y"
    { (yyval.value) = (yyvsp[(1) - (1)].value);}
    break;

  case 28:
/* Line 1792 of yacc.c  */
#line 280 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_value_range(talloc_tos(), (yyvsp[(1) - (3)].value), (yyvsp[(3) - (3)].value));
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 29:
/* Line 1792 of yacc.c  */
#line 286 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_date_range_shortcut(talloc_tos(), (yyvsp[(1) - (1)].daterange));
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 30:
/* Line 1792 of yacc.c  */
#line 292 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_size_range_shortcut(talloc_tos(), (yyvsp[(1) - (1)].sizerange));
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 31:
/* Line 1792 of yacc.c  */
#line 301 "wsp_aqs_parser.y"
    { (yyval.daterange) = eTODAY; }
    break;

  case 32:
/* Line 1792 of yacc.c  */
#line 302 "wsp_aqs_parser.y"
    { (yyval.daterange) = eYESTERDAY; }
    break;

  case 33:
/* Line 1792 of yacc.c  */
#line 303 "wsp_aqs_parser.y"
    { (yyval.daterange) = eTHISWEEK; }
    break;

  case 34:
/* Line 1792 of yacc.c  */
#line 304 "wsp_aqs_parser.y"
    { (yyval.daterange) = eLASTWEEK; }
    break;

  case 35:
/* Line 1792 of yacc.c  */
#line 305 "wsp_aqs_parser.y"
    { (yyval.daterange) = eTHISMONTH; }
    break;

  case 36:
/* Line 1792 of yacc.c  */
#line 306 "wsp_aqs_parser.y"
    { (yyval.daterange) = eTHISMONTH; }
    break;

  case 37:
/* Line 1792 of yacc.c  */
#line 307 "wsp_aqs_parser.y"
    { (yyval.daterange) = eTHISYEAR; }
    break;

  case 38:
/* Line 1792 of yacc.c  */
#line 308 "wsp_aqs_parser.y"
    { (yyval.daterange) = eLASTYEAR; }
    break;

  case 39:
/* Line 1792 of yacc.c  */
#line 312 "wsp_aqs_parser.y"
    { (yyval.sizerange) = eEMPTY; }
    break;

  case 40:
/* Line 1792 of yacc.c  */
#line 313 "wsp_aqs_parser.y"
    { (yyval.sizerange) = eTINY; }
    break;

  case 41:
/* Line 1792 of yacc.c  */
#line 314 "wsp_aqs_parser.y"
    { (yyval.sizerange) = eSMALL; }
    break;

  case 42:
/* Line 1792 of yacc.c  */
#line 315 "wsp_aqs_parser.y"
    { (yyval.sizerange) = eMEDIUM; }
    break;

  case 43:
/* Line 1792 of yacc.c  */
#line 316 "wsp_aqs_parser.y"
    { (yyval.sizerange) = eLARGE; }
    break;

  case 44:
/* Line 1792 of yacc.c  */
#line 317 "wsp_aqs_parser.y"
    { (yyval.sizerange) = eHUGE; }
    break;

  case 45:
/* Line 1792 of yacc.c  */
#line 318 "wsp_aqs_parser.y"
    { (yyval.sizerange) = eGIGANTIC; }
    break;

  case 46:
/* Line 1792 of yacc.c  */
#line 322 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_num_val(talloc_tos(), (yyvsp[(1) - (1)].num));
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 47:
/* Line 1792 of yacc.c  */
#line 328 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_num_val(talloc_tos(), (yyvsp[(1) - (2)].num) * 1024);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 48:
/* Line 1792 of yacc.c  */
#line 334 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_num_val( talloc_tos(), (yyvsp[(1) - (2)].num) * 1024 * 1024);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 49:
/* Line 1792 of yacc.c  */
#line 340 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_num_val(talloc_tos(), (yyvsp[(1) - (2)].num) * 1024 * 1024 * 1024);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 50:
/* Line 1792 of yacc.c  */
#line 346 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_num_val(talloc_tos(),
				    (yyvsp[(1) - (2)].num) * 1024 * 1024 * 1024 * 1024);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 51:
/* Line 1792 of yacc.c  */
#line 353 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_num_val(talloc_tos(), (yyvsp[(1) - (2)].num) * 1000);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 52:
/* Line 1792 of yacc.c  */
#line 359 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_num_val( talloc_tos(), (yyvsp[(1) - (2)].num) * 1000 * 1000);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 53:
/* Line 1792 of yacc.c  */
#line 365 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_num_val(talloc_tos(), (yyvsp[(1) - (2)].num) * 1000 * 1000 * 1000);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 54:
/* Line 1792 of yacc.c  */
#line 371 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_num_val(talloc_tos(),
				    (yyvsp[(1) - (2)].num) * 1000 * 1000 * 1000 * 1000);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 55:
/* Line 1792 of yacc.c  */
#line 378 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_bool_val(talloc_tos(), true);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 56:
/* Line 1792 of yacc.c  */
#line 384 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_num_val(talloc_tos(), false);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 57:
/* Line 1792 of yacc.c  */
#line 390 "wsp_aqs_parser.y"
    {
		char *tmp_str = talloc_strdup(talloc_tos(), (yyvsp[(1) - (1)].strval)+1);
		tmp_str[strlen(tmp_str)-1] = '\0';
		(yyval.value) = create_string_val(talloc_tos(), tmp_str);
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 58:
/* Line 1792 of yacc.c  */
#line 398 "wsp_aqs_parser.y"
    {
		(yyval.value) = create_string_val(talloc_tos(), (yyvsp[(1) - (1)].strval));
		if (!(yyval.value)) {
			 YYERROR;
		}
	}
    break;

  case 59:
/* Line 1792 of yacc.c  */
#line 406 "wsp_aqs_parser.y"
    {
		(yyval.restr) = create_restr(talloc_tos(), eVALUE, NULL, NULL, (yyvsp[(1) - (1)].bas_rest));
		if (!(yyval.restr)) {
			 YYERROR;
		}
	}
    break;

  case 60:
/* Line 1792 of yacc.c  */
#line 412 "wsp_aqs_parser.y"
    {
		(yyval.restr) = create_restr(talloc_tos(), eAND, (yyvsp[(1) - (3)].restr), (yyvsp[(3) - (3)].restr), NULL);
		if (!(yyval.restr)) {
			 YYERROR;
		}
	}
    break;

  case 61:
/* Line 1792 of yacc.c  */
#line 418 "wsp_aqs_parser.y"
    {
		(yyval.restr) = create_restr(talloc_tos(), eOR, (yyvsp[(1) - (3)].restr), (yyvsp[(3) - (3)].restr), NULL);
		if (!(yyval.restr)) {
			 YYERROR;
		}
	}
    break;


/* Line 1792 of yacc.c  */
#line 2087 "wsp_aqs_parser.c"
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (select, scanner, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (select, scanner, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval, select, scanner);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp, select, scanner);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
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

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (select, scanner, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, select, scanner);
    }
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp, select, scanner);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


/* Line 2055 of yacc.c  */
#line 425 "wsp_aqs_parser.y"

