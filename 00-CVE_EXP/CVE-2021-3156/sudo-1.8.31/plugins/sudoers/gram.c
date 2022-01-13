/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define yyparse sudoersparse
#define yylex sudoerslex
#define yyerror sudoerserror
#define yychar sudoerschar
#define yyval sudoersval
#define yylval sudoerslval
#define yydebug sudoersdebug
#define yynerrs sudoersnerrs
#define yyerrflag sudoerserrflag
#define yyss sudoersss
#define yysslim sudoerssslim
#define yyssp sudoersssp
#define yyvs sudoersvs
#define yyvsp sudoersvsp
#define yystacksize sudoersstacksize
#define yylhs sudoerslhs
#define yylen sudoerslen
#define yydefred sudoersdefred
#define yydgoto sudoersdgoto
#define yysindex sudoerssindex
#define yyrindex sudoersrindex
#define yygindex sudoersgindex
#define yytable sudoerstable
#define yycheck sudoerscheck
#define yyname sudoersname
#define yyrule sudoersrule
#define YYPREFIX "sudoers"
#line 2 "gram.y"
/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1996, 1998-2005, 2007-2013, 2014-2018
 *	Todd C. Miller <Todd.Miller@sudo.ws>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#if defined(YYBISON) && defined(HAVE_ALLOCA_H) && !defined(__GNUC__)
# include <alloca.h>
#endif /* YYBISON && HAVE_ALLOCA_H && !__GNUC__ */
#include <errno.h>

#include "sudoers.h"
#include "sudo_digest.h"
#include "toke.h"

/* If we last saw a newline the entry is on the preceding line. */
#define this_lineno	(last_token == COMMENT ? sudolineno - 1 : sudolineno)

/*
 * Globals
 */
bool sudoers_warnings = true;
bool sudoers_strict = false;
bool parse_error = false;
int errorlineno = -1;
char *errorfile = NULL;

struct sudoers_parse_tree parsed_policy = {
    TAILQ_HEAD_INITIALIZER(parsed_policy.userspecs),
    TAILQ_HEAD_INITIALIZER(parsed_policy.defaults),
    NULL, /* aliases */
    NULL, /* lhost */
    NULL /* shost */
};

/*
 * Local protoypes
 */
static void init_options(struct command_options *opts);
static bool add_defaults(int, struct member *, struct defaults *);
static bool add_userspec(struct member *, struct privilege *);
static struct defaults *new_default(char *, char *, short);
static struct member *new_member(char *, int);
static struct command_digest *new_digest(int, char *);
#line 83 "gram.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
    struct cmndspec *cmndspec;
    struct defaults *defaults;
    struct member *member;
    struct runascontainer *runas;
    struct privilege *privilege;
    struct command_digest *digest;
    struct sudo_command command;
    struct command_options options;
    struct cmndtag tag;
    char *string;
    int tok;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 136 "gram.c"
#define COMMAND 257
#define ALIAS 258
#define DEFVAR 259
#define NTWKADDR 260
#define NETGROUP 261
#define USERGROUP 262
#define WORD 263
#define DIGEST 264
#define DEFAULTS 265
#define DEFAULTS_HOST 266
#define DEFAULTS_USER 267
#define DEFAULTS_RUNAS 268
#define DEFAULTS_CMND 269
#define NOPASSWD 270
#define PASSWD 271
#define NOEXEC 272
#define EXEC 273
#define SETENV 274
#define NOSETENV 275
#define LOG_INPUT 276
#define NOLOG_INPUT 277
#define LOG_OUTPUT 278
#define NOLOG_OUTPUT 279
#define MAIL 280
#define NOMAIL 281
#define FOLLOWLNK 282
#define NOFOLLOWLNK 283
#define ALL 284
#define COMMENT 285
#define HOSTALIAS 286
#define CMNDALIAS 287
#define USERALIAS 288
#define RUNASALIAS 289
#define ERROR 290
#define TYPE 291
#define ROLE 292
#define PRIVS 293
#define LIMITPRIVS 294
#define CMND_TIMEOUT 295
#define NOTBEFORE 296
#define NOTAFTER 297
#define MYSELF 298
#define SHA224_TOK 299
#define SHA256_TOK 300
#define SHA384_TOK 301
#define SHA512_TOK 302
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerslhs[] =
#else
short sudoerslhs[] =
#endif
	{                                        -1,
    0,    0,   32,   32,   33,   33,   33,   33,   33,   33,
   33,   33,   33,   33,   33,   33,    4,    4,    3,    3,
    3,    3,    3,   21,   21,   20,   11,   11,    9,    9,
    9,    9,    9,    2,    2,    1,   31,   31,   31,   31,
    7,    7,    6,    6,   28,   29,   30,   24,   25,   26,
   27,   18,   18,   19,   19,   19,   19,   19,   23,   23,
   23,   23,   23,   23,   23,   23,   22,   22,   22,   22,
   22,   22,   22,   22,   22,   22,   22,   22,   22,   22,
   22,    5,    5,    5,   35,   35,   38,   10,   10,   36,
   36,   39,    8,    8,   37,   37,   40,   34,   34,   41,
   14,   14,   12,   12,   13,   13,   13,   13,   13,   17,
   17,   15,   15,   16,   16,   16,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerslen[] =
#else
short sudoerslen[] =
#endif
	{                                         2,
    0,    1,    1,    2,    1,    2,    2,    2,    2,    2,
    2,    2,    3,    3,    3,    3,    1,    3,    1,    2,
    3,    3,    3,    1,    3,    3,    1,    2,    1,    1,
    1,    1,    1,    1,    3,    4,    3,    3,    3,    3,
    1,    2,    1,    2,    3,    3,    3,    3,    3,    3,
    3,    0,    3,    0,    1,    3,    2,    1,    0,    2,
    2,    2,    2,    2,    2,    2,    0,    2,    2,    2,
    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,
    2,    1,    1,    1,    1,    3,    3,    1,    3,    1,
    3,    3,    1,    3,    1,    3,    3,    1,    3,    3,
    1,    3,    1,    2,    1,    1,    1,    1,    1,    1,
    3,    1,    2,    1,    1,    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersdefred[] =
#else
short sudoersdefred[] =
#endif
	{                                      0,
    0,  105,  107,  108,  109,    0,    0,    0,    0,    0,
  106,    5,    0,    0,    0,    0,    0,    0,  101,  103,
    0,    0,    3,    6,    0,    0,   17,    0,   29,   32,
   31,   33,   30,    0,   27,    0,   88,    0,    0,   84,
   83,   82,    0,    0,    0,    0,    0,   43,   41,   93,
    0,    0,    0,    0,   85,    0,    0,   90,    0,    0,
   98,    0,    0,   95,  104,    0,    0,   24,    0,    4,
    0,    0,    0,   20,    0,   28,    0,    0,    0,    0,
   44,    0,    0,    0,    0,    0,    0,   42,    0,    0,
    0,    0,    0,    0,    0,    0,  102,    0,    0,   21,
   22,   23,   18,   89,   37,   38,   39,   40,   94,    0,
   86,    0,   91,    0,   99,    0,   96,    0,   34,    0,
   59,   25,    0,    0,    0,    0,    0,  114,  116,  115,
    0,  110,  112,    0,    0,   53,   35,    0,    0,    0,
    0,    0,    0,    0,    0,   63,   64,   65,   66,   62,
   60,   61,  113,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   68,   69,   70,   71,   72,   73,   74,   75,
   76,   77,   80,   81,   78,   79,   36,  111,   49,   48,
   50,   51,   45,   46,   47,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersdgoto[] =
#else
short sudoersdgoto[] =
#endif
	{                                      18,
  119,  120,   27,   28,   48,   49,   50,   51,   35,   67,
   37,   19,   20,   21,  132,  133,  134,  121,  125,   68,
   69,  145,  127,  146,  147,  148,  149,  150,  151,  152,
   52,   22,   23,   60,   54,   57,   63,   55,   58,   64,
   61,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerssindex[] =
#else
short sudoerssindex[] =
#endif
	{                                    512,
 -272,    0,    0,    0,    0,  -23,  227,  -19,  -19,   -5,
    0,    0, -239, -236, -234, -232, -231,    0,    0,    0,
  -33,  512,    0,    0,   -3, -220,    0,    3,    0,    0,
    0,    0,    0, -225,    0,  -28,    0,  -24,  -24,    0,
    0,    0, -240,  -15,   -8,    2,    4,    0,    0,    0,
  -21,  -12,   -9,    6,    0,    7,   12,    0,   10,   14,
    0,   13,   25,    0,    0,  -19,  -36,    0,   26,    0,
 -208, -202, -198,    0,  -23,    0,  227,    3,    3,    3,
    0, -179, -178, -174, -173,   -5,    3,    0,  227, -239,
   -5, -236,  -19, -234,  -19, -232,    0,   52,  227,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   50,
    0,   51,    0,   54,    0,   54,    0,  -29,    0,   55,
    0,    0,  289,   -7,   59,   52, -216,    0,    0,    0,
 -217,    0,    0,   57,  289,    0,    0,   32,   41,   42,
   43,   44,   45,   47,  450,    0,    0,    0,    0,    0,
    0,    0,    0,  289,   57, -154, -153, -150, -149, -148,
 -147, -146,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersrindex[] =
#else
short sudoersrindex[] =
#endif
	{                                    118,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  119,    0,    0,    1,    0,    0,  145,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  159,    0,    0,  193,    0,    0,  207,
    0,    0,  241,    0,    0,    0,    0,    0,  275,    0,
    0,    0,    0,    0,    0,    0,    0,  309,  323,  357,
    0,    0,    0,    0,    0,    0,  371,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  404,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   15,
    0,   49,    0,   63,    0,   97,    0,   79,    0,  111,
    0,    0,   81,   82,    0,  404,  483,    0,    0,    0,
    0,    0,    0,   83,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   84,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersgindex[] =
#else
short sudoersgindex[] =
#endif
	{                                      0,
    5,    0,   53,   18,   86,   74,  -79,   36,   98,   -1,
   56,   68,  120,   -6,  -18,    8,   11,    0,    0,   39,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  113,    0,    0,    0,    0,   58,   48,   46,
   60,
};
#define YYTABLESIZE 801
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerstable[] =
#else
short sudoerstable[] =
#endif
	{                                      34,
   19,   38,   39,   17,   26,   36,  109,   77,   26,   26,
   66,   26,   24,   17,   87,   77,   40,   41,   53,   66,
   43,   56,   86,   59,   98,   62,    2,   43,  123,    3,
    4,    5,   29,   19,   30,   31,   66,   32,   74,   72,
  128,   73,   82,   42,   19,  129,   75,   87,   92,   83,
  135,   89,   11,   78,  100,   79,   80,   71,   33,   84,
  101,   85,  100,   90,  102,  177,  130,   91,   87,   92,
   93,   94,   87,   95,  138,  139,  140,  141,  142,  143,
  144,   92,   96,   99,  105,  106,  114,  110,  116,  107,
  108,  118,  156,   77,   86,  100,   97,   66,  126,  136,
  154,  157,  158,  159,  160,  161,   92,  162,  179,  180,
   26,  124,  181,  182,  183,  184,  185,    1,    2,   54,
  100,   58,   55,   57,   56,   88,  112,  103,   81,   97,
  137,   76,  104,   97,   70,  178,   65,  122,  153,  113,
    0,  117,    0,   26,   12,  155,    0,  111,    0,    0,
    0,    0,    0,  115,   97,    0,    0,    0,    9,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   26,    0,
    0,    0,    0,    0,    0,    0,    0,   12,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    9,   10,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    8,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   29,   10,   30,   31,    2,   32,
   25,    3,    4,    5,   25,   25,    0,   25,    2,    8,
   11,    3,    4,    5,   40,   41,    0,    0,    0,    0,
   33,   40,   41,    0,   11,    0,   19,    0,   19,   34,
    0,   19,   19,   19,   11,   19,   19,   19,   19,   19,
   87,   42,   87,   11,    7,   87,   87,   87,   42,   87,
   87,   87,   87,   87,   19,   19,   19,   19,   19,   19,
    0,    0,    0,   44,   45,   46,   47,    0,   87,   87,
   87,   87,   87,   87,   92,    0,   92,    7,   15,   92,
   92,   92,    0,   92,   92,   92,   92,   92,  100,    0,
  100,  131,   13,  100,  100,  100,    0,  100,  100,  100,
  100,  100,   92,   92,   92,   92,   92,   92,    0,    0,
    0,   15,    0,    0,    0,    0,  100,  100,  100,  100,
  100,  100,   97,    0,   97,   13,   14,   97,   97,   97,
    0,   97,   97,   97,   97,   97,   26,    0,   26,    0,
   16,   26,   26,   26,    0,   26,   26,   26,   26,   26,
   97,   97,   97,   97,   97,   97,    0,    0,    0,   14,
    0,    0,    0,    0,   26,   26,   26,   26,   26,   26,
   12,    0,   12,   16,    0,   12,   12,   12,    0,   12,
   12,   12,   12,   12,    9,    0,    9,    0,    0,    9,
    9,    9,    0,    9,    9,    9,    9,    9,   12,   12,
   12,   12,   12,   12,    0,    0,   52,    0,    0,    0,
    0,    0,    9,    9,    9,    9,    9,    9,   10,    0,
   10,    0,    0,   10,   10,   10,    0,   10,   10,   10,
   10,   10,    8,    0,    8,    0,    0,    8,    8,    8,
    0,    8,    8,    8,    8,    8,   10,   10,   10,   10,
   10,   10,   43,    0,   29,    0,   30,   31,    0,   32,
    8,    8,    8,    8,    8,    8,   11,    0,   11,    0,
    0,   11,   11,   11,    0,   11,   11,   11,   11,   11,
   33,    0,    0,    0,    0,   67,    0,    0,    0,    0,
    0,    0,    0,    0,   11,   11,   11,   11,   11,   11,
    7,    0,    7,    0,    0,    7,    7,    7,    0,    7,
    7,    7,    7,    7,   17,    0,  128,    0,    0,    0,
    0,  129,    0,    0,    0,    0,    0,    0,    7,    7,
    7,    7,    7,    7,   15,    0,   15,    0,    0,   15,
   15,   15,  130,   15,   15,   15,   15,   15,   13,    0,
   13,    0,    0,   13,   13,   13,    0,   13,   13,   13,
   13,   13,   15,   15,   15,   15,   15,   15,    0,    0,
    0,    0,    0,    0,    0,    0,   13,   13,   13,   13,
   13,   13,   14,    0,   14,    0,    0,   14,   14,   14,
    0,   14,   14,   14,   14,   14,   16,    0,   16,    0,
    0,   16,   16,   16,    0,   16,   16,   16,   16,   16,
   14,   14,   14,   14,   14,   14,    0,    0,    0,    0,
    0,    0,    0,    0,   16,   16,   16,   16,   16,   16,
   52,   52,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   52,   52,   52,   52,   52,   52,   52,
   52,   52,   52,   52,   52,   52,   52,   52,    0,    0,
    0,    0,    0,    0,   52,   52,   52,   52,   52,   52,
   52,    0,   52,   52,   52,   52,   40,   41,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  163,
  164,  165,  166,  167,  168,  169,  170,  171,  172,  173,
  174,  175,  176,   42,    0,    0,    0,    0,    0,   67,
   67,    0,    0,    0,    0,    0,    0,    0,   44,   45,
   46,   47,   67,   67,   67,   67,   67,   67,   67,   67,
   67,   67,   67,   67,   67,   67,   67,    1,    0,    2,
    0,    0,    3,    4,    5,    0,    6,    7,    8,    9,
   10,   67,   67,   67,   67,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   11,   12,   13,   14,   15,
   16,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerscheck[] =
#else
short sudoerscheck[] =
#endif
	{                                      33,
    0,    8,    9,   33,   33,    7,   86,   44,   33,   33,
   44,   33,  285,   33,    0,   44,  257,  258,  258,   44,
   33,  258,   44,  258,   61,  258,  258,   33,   58,  261,
  262,  263,  258,   33,  260,  261,   44,  263,  259,   43,
  258,   45,   58,  284,   44,  263,   44,   33,    0,   58,
   58,   61,  284,   36,  263,   38,   39,   61,  284,   58,
  263,   58,    0,   58,  263,  145,  284,   61,   51,   58,
   61,   58,   58,   61,  291,  292,  293,  294,  295,  296,
  297,   33,   58,   58,  264,  264,   93,   89,   95,  264,
  264,   40,   61,   44,   44,   33,    0,   44,   44,   41,
   44,   61,   61,   61,   61,   61,   58,   61,  263,  263,
    0,  118,  263,  263,  263,  263,  263,    0,    0,   41,
   58,   41,   41,   41,   41,   52,   91,   75,   43,   33,
  126,   34,   77,   66,   22,  154,   17,   99,  131,   92,
   -1,   96,   -1,   33,    0,  135,   -1,   90,   -1,   -1,
   -1,   -1,   -1,   94,   58,   -1,   -1,   -1,    0,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   58,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   33,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   33,    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  258,   33,  260,  261,  258,  263,
  259,  261,  262,  263,  259,  259,   -1,  259,  258,   33,
    0,  261,  262,  263,  257,  258,   -1,   -1,   -1,   -1,
  284,  257,  258,   -1,  284,   -1,  256,   -1,  258,   33,
   -1,  261,  262,  263,  284,  265,  266,  267,  268,  269,
  256,  284,  258,   33,    0,  261,  262,  263,  284,  265,
  266,  267,  268,  269,  284,  285,  286,  287,  288,  289,
   -1,   -1,   -1,  299,  300,  301,  302,   -1,  284,  285,
  286,  287,  288,  289,  256,   -1,  258,   33,    0,  261,
  262,  263,   -1,  265,  266,  267,  268,  269,  256,   -1,
  258,   33,    0,  261,  262,  263,   -1,  265,  266,  267,
  268,  269,  284,  285,  286,  287,  288,  289,   -1,   -1,
   -1,   33,   -1,   -1,   -1,   -1,  284,  285,  286,  287,
  288,  289,  256,   -1,  258,   33,    0,  261,  262,  263,
   -1,  265,  266,  267,  268,  269,  256,   -1,  258,   -1,
    0,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
  284,  285,  286,  287,  288,  289,   -1,   -1,   -1,   33,
   -1,   -1,   -1,   -1,  284,  285,  286,  287,  288,  289,
  256,   -1,  258,   33,   -1,  261,  262,  263,   -1,  265,
  266,  267,  268,  269,  256,   -1,  258,   -1,   -1,  261,
  262,  263,   -1,  265,  266,  267,  268,  269,  284,  285,
  286,  287,  288,  289,   -1,   -1,   33,   -1,   -1,   -1,
   -1,   -1,  284,  285,  286,  287,  288,  289,  256,   -1,
  258,   -1,   -1,  261,  262,  263,   -1,  265,  266,  267,
  268,  269,  256,   -1,  258,   -1,   -1,  261,  262,  263,
   -1,  265,  266,  267,  268,  269,  284,  285,  286,  287,
  288,  289,   33,   -1,  258,   -1,  260,  261,   -1,  263,
  284,  285,  286,  287,  288,  289,  256,   -1,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
  284,   -1,   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  284,  285,  286,  287,  288,  289,
  256,   -1,  258,   -1,   -1,  261,  262,  263,   -1,  265,
  266,  267,  268,  269,   33,   -1,  258,   -1,   -1,   -1,
   -1,  263,   -1,   -1,   -1,   -1,   -1,   -1,  284,  285,
  286,  287,  288,  289,  256,   -1,  258,   -1,   -1,  261,
  262,  263,  284,  265,  266,  267,  268,  269,  256,   -1,
  258,   -1,   -1,  261,  262,  263,   -1,  265,  266,  267,
  268,  269,  284,  285,  286,  287,  288,  289,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  284,  285,  286,  287,
  288,  289,  256,   -1,  258,   -1,   -1,  261,  262,  263,
   -1,  265,  266,  267,  268,  269,  256,   -1,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
  284,  285,  286,  287,  288,  289,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  284,  285,  286,  287,  288,  289,
  257,  258,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  270,  271,  272,  273,  274,  275,  276,
  277,  278,  279,  280,  281,  282,  283,  284,   -1,   -1,
   -1,   -1,   -1,   -1,  291,  292,  293,  294,  295,  296,
  297,   -1,  299,  300,  301,  302,  257,  258,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  270,
  271,  272,  273,  274,  275,  276,  277,  278,  279,  280,
  281,  282,  283,  284,   -1,   -1,   -1,   -1,   -1,  257,
  258,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  299,  300,
  301,  302,  270,  271,  272,  273,  274,  275,  276,  277,
  278,  279,  280,  281,  282,  283,  284,  256,   -1,  258,
   -1,   -1,  261,  262,  263,   -1,  265,  266,  267,  268,
  269,  299,  300,  301,  302,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  284,  285,  286,  287,  288,
  289,
};
#define YYFINAL 18
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 302
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
const char * const sudoersname[] =
#else
char *sudoersname[] =
#endif
	{
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,0,0,0,"'('","')'",0,"'+'","','","'-'",0,0,0,0,0,0,0,0,0,0,0,0,"':'",
0,0,"'='",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"COMMAND","ALIAS","DEFVAR","NTWKADDR","NETGROUP","USERGROUP","WORD","DIGEST",
"DEFAULTS","DEFAULTS_HOST","DEFAULTS_USER","DEFAULTS_RUNAS","DEFAULTS_CMND",
"NOPASSWD","PASSWD","NOEXEC","EXEC","SETENV","NOSETENV","LOG_INPUT",
"NOLOG_INPUT","LOG_OUTPUT","NOLOG_OUTPUT","MAIL","NOMAIL","FOLLOWLNK",
"NOFOLLOWLNK","ALL","COMMENT","HOSTALIAS","CMNDALIAS","USERALIAS","RUNASALIAS",
"ERROR","TYPE","ROLE","PRIVS","LIMITPRIVS","CMND_TIMEOUT","NOTBEFORE",
"NOTAFTER","MYSELF","SHA224_TOK","SHA256_TOK","SHA384_TOK","SHA512_TOK",
};
#if defined(__cplusplus) || defined(__STDC__)
const char * const sudoersrule[] =
#else
char *sudoersrule[] =
#endif
	{"$accept : file",
"file :",
"file : line",
"line : entry",
"line : line entry",
"entry : COMMENT",
"entry : error COMMENT",
"entry : userlist privileges",
"entry : USERALIAS useraliases",
"entry : HOSTALIAS hostaliases",
"entry : CMNDALIAS cmndaliases",
"entry : RUNASALIAS runasaliases",
"entry : DEFAULTS defaults_list",
"entry : DEFAULTS_USER userlist defaults_list",
"entry : DEFAULTS_RUNAS userlist defaults_list",
"entry : DEFAULTS_HOST hostlist defaults_list",
"entry : DEFAULTS_CMND cmndlist defaults_list",
"defaults_list : defaults_entry",
"defaults_list : defaults_list ',' defaults_entry",
"defaults_entry : DEFVAR",
"defaults_entry : '!' DEFVAR",
"defaults_entry : DEFVAR '=' WORD",
"defaults_entry : DEFVAR '+' WORD",
"defaults_entry : DEFVAR '-' WORD",
"privileges : privilege",
"privileges : privileges ':' privilege",
"privilege : hostlist '=' cmndspeclist",
"ophost : host",
"ophost : '!' host",
"host : ALIAS",
"host : ALL",
"host : NETGROUP",
"host : NTWKADDR",
"host : WORD",
"cmndspeclist : cmndspec",
"cmndspeclist : cmndspeclist ',' cmndspec",
"cmndspec : runasspec options cmndtag digcmnd",
"digest : SHA224_TOK ':' DIGEST",
"digest : SHA256_TOK ':' DIGEST",
"digest : SHA384_TOK ':' DIGEST",
"digest : SHA512_TOK ':' DIGEST",
"digcmnd : opcmnd",
"digcmnd : digest opcmnd",
"opcmnd : cmnd",
"opcmnd : '!' cmnd",
"timeoutspec : CMND_TIMEOUT '=' WORD",
"notbeforespec : NOTBEFORE '=' WORD",
"notafterspec : NOTAFTER '=' WORD",
"rolespec : ROLE '=' WORD",
"typespec : TYPE '=' WORD",
"privsspec : PRIVS '=' WORD",
"limitprivsspec : LIMITPRIVS '=' WORD",
"runasspec :",
"runasspec : '(' runaslist ')'",
"runaslist :",
"runaslist : userlist",
"runaslist : userlist ':' grouplist",
"runaslist : ':' grouplist",
"runaslist : ':'",
"options :",
"options : options notbeforespec",
"options : options notafterspec",
"options : options timeoutspec",
"options : options rolespec",
"options : options typespec",
"options : options privsspec",
"options : options limitprivsspec",
"cmndtag :",
"cmndtag : cmndtag NOPASSWD",
"cmndtag : cmndtag PASSWD",
"cmndtag : cmndtag NOEXEC",
"cmndtag : cmndtag EXEC",
"cmndtag : cmndtag SETENV",
"cmndtag : cmndtag NOSETENV",
"cmndtag : cmndtag LOG_INPUT",
"cmndtag : cmndtag NOLOG_INPUT",
"cmndtag : cmndtag LOG_OUTPUT",
"cmndtag : cmndtag NOLOG_OUTPUT",
"cmndtag : cmndtag FOLLOWLNK",
"cmndtag : cmndtag NOFOLLOWLNK",
"cmndtag : cmndtag MAIL",
"cmndtag : cmndtag NOMAIL",
"cmnd : ALL",
"cmnd : ALIAS",
"cmnd : COMMAND",
"hostaliases : hostalias",
"hostaliases : hostaliases ':' hostalias",
"hostalias : ALIAS '=' hostlist",
"hostlist : ophost",
"hostlist : hostlist ',' ophost",
"cmndaliases : cmndalias",
"cmndaliases : cmndaliases ':' cmndalias",
"cmndalias : ALIAS '=' cmndlist",
"cmndlist : digcmnd",
"cmndlist : cmndlist ',' digcmnd",
"runasaliases : runasalias",
"runasaliases : runasaliases ':' runasalias",
"runasalias : ALIAS '=' userlist",
"useraliases : useralias",
"useraliases : useraliases ':' useralias",
"useralias : ALIAS '=' userlist",
"userlist : opuser",
"userlist : userlist ',' opuser",
"opuser : user",
"opuser : '!' user",
"user : ALIAS",
"user : ALL",
"user : NETGROUP",
"user : USERGROUP",
"user : WORD",
"grouplist : opgroup",
"grouplist : grouplist ',' opgroup",
"opgroup : group",
"opgroup : '!' group",
"group : ALIAS",
"group : ALL",
"group : WORD",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
/* LINTUSED */
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
unsigned int yystacksize;
int yyparse(void);
#line 911 "gram.y"
void
sudoerserror(const char *s)
{
    debug_decl(sudoerserror, SUDOERS_DEBUG_PARSER)

    /* Save the line the first error occurred on. */
    if (errorlineno == -1) {
	errorlineno = this_lineno;
	rcstr_delref(errorfile);
	errorfile = rcstr_addref(sudoers);
    }
    if (sudoers_warnings && s != NULL) {
	LEXTRACE("<*> ");
#ifndef TRACELEXER
	if (trace_print == NULL || trace_print == sudoers_trace_print) {
	    const char fmt[] = ">>> %s: %s near line %d <<<\n";
	    int oldlocale;

	    /* Warnings are displayed in the user's locale. */
	    sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);
	    sudo_printf(SUDO_CONV_ERROR_MSG, _(fmt), sudoers, _(s), this_lineno);
	    sudoers_setlocale(oldlocale, NULL);
	}
#endif
    }
    parse_error = true;
    debug_return;
}

static struct defaults *
new_default(char *var, char *val, short op)
{
    struct defaults *d;
    debug_decl(new_default, SUDOERS_DEBUG_PARSER)

    if ((d = calloc(1, sizeof(struct defaults))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    d->var = var;
    d->val = val;
    /* d->type = 0; */
    d->op = op;
    /* d->binding = NULL */
    d->lineno = this_lineno;
    d->file = rcstr_addref(sudoers);
    HLTQ_INIT(d, entries);

    debug_return_ptr(d);
}

static struct member *
new_member(char *name, int type)
{
    struct member *m;
    debug_decl(new_member, SUDOERS_DEBUG_PARSER)

    if ((m = calloc(1, sizeof(struct member))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    m->name = name;
    m->type = type;
    HLTQ_INIT(m, entries);

    debug_return_ptr(m);
}

static struct command_digest *
new_digest(int digest_type, char *digest_str)
{
    struct command_digest *digest;
    debug_decl(new_digest, SUDOERS_DEBUG_PARSER)

    if ((digest = malloc(sizeof(*digest))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    digest->digest_type = digest_type;
    digest->digest_str = digest_str;
    if (digest->digest_str == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	free(digest);
	digest = NULL;
    }

    debug_return_ptr(digest);
}

/*
 * Add a list of defaults structures to the defaults list.
 * The binding, if non-NULL, specifies a list of hosts, users, or
 * runas users the entries apply to (specified by the type).
 */
static bool
add_defaults(int type, struct member *bmem, struct defaults *defs)
{
    struct defaults *d, *next;
    struct member_list *binding;
    bool ret = true;
    debug_decl(add_defaults, SUDOERS_DEBUG_PARSER)

    if (defs != NULL) {
	/*
	 * We use a single binding for each entry in defs.
	 */
	if ((binding = malloc(sizeof(*binding))) == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to allocate memory");
	    sudoerserror(N_("unable to allocate memory"));
	    debug_return_bool(false);
	}
	if (bmem != NULL)
	    HLTQ_TO_TAILQ(binding, bmem, entries);
	else
	    TAILQ_INIT(binding);

	/*
	 * Set type and binding (who it applies to) for new entries.
	 * Then add to the global defaults list.
	 */
	HLTQ_FOREACH_SAFE(d, defs, entries, next) {
	    d->type = type;
	    d->binding = binding;
	    TAILQ_INSERT_TAIL(&parsed_policy.defaults, d, entries);
	}
    }

    debug_return_bool(ret);
}

/*
 * Allocate a new struct userspec, populate it, and insert it at the
 * end of the userspecs list.
 */
static bool
add_userspec(struct member *members, struct privilege *privs)
{
    struct userspec *u;
    debug_decl(add_userspec, SUDOERS_DEBUG_PARSER)

    if ((u = calloc(1, sizeof(*u))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_bool(false);
    }
    u->lineno = this_lineno;
    u->file = rcstr_addref(sudoers);
    HLTQ_TO_TAILQ(&u->users, members, entries);
    HLTQ_TO_TAILQ(&u->privileges, privs, entries);
    STAILQ_INIT(&u->comments);
    TAILQ_INSERT_TAIL(&parsed_policy.userspecs, u, entries);

    debug_return_bool(true);
}

/*
 * Free a member struct and its contents.
 */
void
free_member(struct member *m)
{
    debug_decl(free_member, SUDOERS_DEBUG_PARSER)

    if (m->type == COMMAND) {
	    struct sudo_command *c = (struct sudo_command *)m->name;
	    free(c->cmnd);
	    free(c->args);
	    if (c->digest != NULL) {
		free(c->digest->digest_str);
		free(c->digest);
	    }
    }
    free(m->name);
    free(m);

    debug_return;
}

/*
 * Free a tailq of members but not the struct member_list container itself.
 */
void
free_members(struct member_list *members)
{
    struct member *m;
    debug_decl(free_members, SUDOERS_DEBUG_PARSER)

    while ((m = TAILQ_FIRST(members)) != NULL) {
	TAILQ_REMOVE(members, m, entries);
	free_member(m);
    }

    debug_return;
}

void
free_defaults(struct defaults_list *defs)
{
    struct member_list *prev_binding = NULL;
    struct defaults *def;
    debug_decl(free_defaults, SUDOERS_DEBUG_PARSER)

    while ((def = TAILQ_FIRST(defs)) != NULL) {
	TAILQ_REMOVE(defs, def, entries);
	free_default(def, &prev_binding);
    }

    debug_return;
}

void
free_default(struct defaults *def, struct member_list **binding)
{
    debug_decl(free_default, SUDOERS_DEBUG_PARSER)

    if (def->binding != *binding) {
	*binding = def->binding;
	if (def->binding != NULL) {
	    free_members(def->binding);
	    free(def->binding);
	}
    }
    rcstr_delref(def->file);
    free(def->var);
    free(def->val);
    free(def);

    debug_return;
}

void
free_privilege(struct privilege *priv)
{
    struct member_list *runasuserlist = NULL, *runasgrouplist = NULL;
    struct member_list *prev_binding = NULL;
    struct cmndspec *cs;
    struct defaults *def;
#ifdef HAVE_SELINUX
    char *role = NULL, *type = NULL;
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
    char *privs = NULL, *limitprivs = NULL;
#endif /* HAVE_PRIV_SET */
    debug_decl(free_privilege, SUDOERS_DEBUG_PARSER)

    free(priv->ldap_role);
    free_members(&priv->hostlist);
    while ((cs = TAILQ_FIRST(&priv->cmndlist)) != NULL) {
	TAILQ_REMOVE(&priv->cmndlist, cs, entries);
#ifdef HAVE_SELINUX
	/* Only free the first instance of a role/type. */
	if (cs->role != role) {
	    role = cs->role;
	    free(cs->role);
	}
	if (cs->type != type) {
	    type = cs->type;
	    free(cs->type);
	}
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
	/* Only free the first instance of privs/limitprivs. */
	if (cs->privs != privs) {
	    privs = cs->privs;
	    free(cs->privs);
	}
	if (cs->limitprivs != limitprivs) {
	    limitprivs = cs->limitprivs;
	    free(cs->limitprivs);
	}
#endif /* HAVE_PRIV_SET */
	/* Only free the first instance of runas user/group lists. */
	if (cs->runasuserlist && cs->runasuserlist != runasuserlist) {
	    runasuserlist = cs->runasuserlist;
	    free_members(runasuserlist);
	    free(runasuserlist);
	}
	if (cs->runasgrouplist && cs->runasgrouplist != runasgrouplist) {
	    runasgrouplist = cs->runasgrouplist;
	    free_members(runasgrouplist);
	    free(runasgrouplist);
	}
	free_member(cs->cmnd);
	free(cs);
    }
    while ((def = TAILQ_FIRST(&priv->defaults)) != NULL) {
	TAILQ_REMOVE(&priv->defaults, def, entries);
	free_default(def, &prev_binding);
    }
    free(priv);

    debug_return;
}

void
free_userspecs(struct userspec_list *usl)
{
    struct userspec *us;
    debug_decl(free_userspecs, SUDOERS_DEBUG_PARSER)

    while ((us = TAILQ_FIRST(usl)) != NULL) {
	TAILQ_REMOVE(usl, us, entries);
	free_userspec(us);
    }

    debug_return;
}

void
free_userspec(struct userspec *us)
{
    struct privilege *priv;
    struct sudoers_comment *comment;
    debug_decl(free_userspec, SUDOERS_DEBUG_PARSER)

    free_members(&us->users);
    while ((priv = TAILQ_FIRST(&us->privileges)) != NULL) {
	TAILQ_REMOVE(&us->privileges, priv, entries);
	free_privilege(priv);
    }
    while ((comment = STAILQ_FIRST(&us->comments)) != NULL) {
	STAILQ_REMOVE_HEAD(&us->comments, entries);
	free(comment->str);
	free(comment);
    }
    rcstr_delref(us->file);
    free(us);

    debug_return;
}

/*
 * Initialized a sudoers parse tree.
 */
void
init_parse_tree(struct sudoers_parse_tree *parse_tree, const char *lhost,
    const char *shost)
{
    TAILQ_INIT(&parse_tree->userspecs);
    TAILQ_INIT(&parse_tree->defaults);
    parse_tree->aliases = NULL;
    parse_tree->shost = shost;
    parse_tree->lhost = lhost;
}

/*
 * Move the contents of parsed_policy to new_tree.
 */
void
reparent_parse_tree(struct sudoers_parse_tree *new_tree)
{
    TAILQ_CONCAT(&new_tree->userspecs, &parsed_policy.userspecs, entries);
    TAILQ_CONCAT(&new_tree->defaults, &parsed_policy.defaults, entries);
    new_tree->aliases = parsed_policy.aliases;
    parsed_policy.aliases = NULL;
}

/*
 * Free the contents of a sudoers parse tree and initialize it.
 */
void
free_parse_tree(struct sudoers_parse_tree *parse_tree)
{
    free_userspecs(&parse_tree->userspecs);
    free_defaults(&parse_tree->defaults);
    free_aliases(parse_tree->aliases);
    parse_tree->aliases = NULL;
}

/*
 * Free up space used by data structures from a previous parser run and sets
 * the current sudoers file to path.
 */
bool
init_parser(const char *path, bool quiet, bool strict)
{
    bool ret = true;
    debug_decl(init_parser, SUDOERS_DEBUG_PARSER)

    free_parse_tree(&parsed_policy);
    init_lexer();

    rcstr_delref(sudoers);
    if (path != NULL) {
	if ((sudoers = rcstr_dup(path)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    ret = false;
	}
    } else {
	sudoers = NULL;
    }

    parse_error = false;
    errorlineno = -1;
    rcstr_delref(errorfile);
    errorfile = NULL;
    sudoers_warnings = !quiet;
    sudoers_strict = strict;

    debug_return_bool(ret);
}

/*
 * Initialize all options in a cmndspec.
 */
static void
init_options(struct command_options *opts)
{
    opts->notbefore = UNSPEC;
    opts->notafter = UNSPEC;
    opts->timeout = UNSPEC;
#ifdef HAVE_SELINUX
    opts->role = NULL;
    opts->type = NULL;
#endif
#ifdef HAVE_PRIV_SET
    opts->privs = NULL;
    opts->limitprivs = NULL;
#endif
}
#line 1053 "gram.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
#if defined(__cplusplus) || defined(__STDC__)
static int yygrowstack(void)
#else
static int yygrowstack()
#endif
{
    unsigned int newsize;
    long sslen;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#ifdef __STDC__
#define YY_SIZE_MAX 0xffffffffU
#else
#define YY_SIZE_MAX (unsigned int)0xffffffff
#endif
#endif
    if (YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    sslen = yyssp - yyss;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + sslen;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + sslen;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
bail:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return -1;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
#if defined(__cplusplus) || defined(__STDC__)
yyparse(void)
#else
yyparse()
#endif
{
    int yym, yyn, yystate;
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
    const char *yys;
#else /* !(defined(__cplusplus) || defined(__STDC__)) */
    char *yys;
#endif /* !(defined(__cplusplus) || defined(__STDC__)) */

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif /* YYDEBUG */

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 1:
#line 181 "gram.y"
{ ; }
break;
case 5:
#line 189 "gram.y"
{
			    ;
			}
break;
case 6:
#line 192 "gram.y"
{
			    yyerrok;
			}
break;
case 7:
#line 195 "gram.y"
{
			    if (!add_userspec(yyvsp[-1].member, yyvsp[0].privilege)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 8:
#line 201 "gram.y"
{
			    ;
			}
break;
case 9:
#line 204 "gram.y"
{
			    ;
			}
break;
case 10:
#line 207 "gram.y"
{
			    ;
			}
break;
case 11:
#line 210 "gram.y"
{
			    ;
			}
break;
case 12:
#line 213 "gram.y"
{
			    if (!add_defaults(DEFAULTS, NULL, yyvsp[0].defaults))
				YYERROR;
			}
break;
case 13:
#line 217 "gram.y"
{
			    if (!add_defaults(DEFAULTS_USER, yyvsp[-1].member, yyvsp[0].defaults))
				YYERROR;
			}
break;
case 14:
#line 221 "gram.y"
{
			    if (!add_defaults(DEFAULTS_RUNAS, yyvsp[-1].member, yyvsp[0].defaults))
				YYERROR;
			}
break;
case 15:
#line 225 "gram.y"
{
			    if (!add_defaults(DEFAULTS_HOST, yyvsp[-1].member, yyvsp[0].defaults))
				YYERROR;
			}
break;
case 16:
#line 229 "gram.y"
{
			    if (!add_defaults(DEFAULTS_CMND, yyvsp[-1].member, yyvsp[0].defaults))
				YYERROR;
			}
break;
case 18:
#line 236 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].defaults, yyvsp[0].defaults, entries);
			    yyval.defaults = yyvsp[-2].defaults;
			}
break;
case 19:
#line 242 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, true);
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 20:
#line 249 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, false);
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 21:
#line 256 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, true);
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 22:
#line 263 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '+');
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 23:
#line 270 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '-');
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 25:
#line 280 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].privilege, yyvsp[0].privilege, entries);
			    yyval.privilege = yyvsp[-2].privilege;
			}
break;
case 26:
#line 286 "gram.y"
{
			    struct privilege *p = calloc(1, sizeof(*p));
			    if (p == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    TAILQ_INIT(&p->defaults);
			    HLTQ_TO_TAILQ(&p->hostlist, yyvsp[-2].member, entries);
			    HLTQ_TO_TAILQ(&p->cmndlist, yyvsp[0].cmndspec, entries);
			    HLTQ_INIT(p, entries);
			    yyval.privilege = p;
			}
break;
case 27:
#line 300 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 28:
#line 304 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 29:
#line 310 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 30:
#line 317 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 31:
#line 324 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 32:
#line 331 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NTWKADDR);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 33:
#line 338 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 35:
#line 348 "gram.y"
{
			    struct cmndspec *prev;
			    prev = HLTQ_LAST(yyvsp[-2].cmndspec, cmndspec, entries);
			    HLTQ_CONCAT(yyvsp[-2].cmndspec, yyvsp[0].cmndspec, entries);
#ifdef HAVE_SELINUX
			    /* propagate role and type */
			    if (yyvsp[0].cmndspec->role == NULL && yyvsp[0].cmndspec->type == NULL) {
				yyvsp[0].cmndspec->role = prev->role;
				yyvsp[0].cmndspec->type = prev->type;
			    }
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
			    /* propagate privs & limitprivs */
			    if (yyvsp[0].cmndspec->privs == NULL && yyvsp[0].cmndspec->limitprivs == NULL) {
			        yyvsp[0].cmndspec->privs = prev->privs;
			        yyvsp[0].cmndspec->limitprivs = prev->limitprivs;
			    }
#endif /* HAVE_PRIV_SET */
			    /* propagate command time restrictions */
			    if (yyvsp[0].cmndspec->notbefore == UNSPEC)
				yyvsp[0].cmndspec->notbefore = prev->notbefore;
			    if (yyvsp[0].cmndspec->notafter == UNSPEC)
				yyvsp[0].cmndspec->notafter = prev->notafter;
			    /* propagate command timeout */
			    if (yyvsp[0].cmndspec->timeout == UNSPEC)
				yyvsp[0].cmndspec->timeout = prev->timeout;
			    /* propagate tags and runas list */
			    if (yyvsp[0].cmndspec->tags.nopasswd == UNSPEC)
				yyvsp[0].cmndspec->tags.nopasswd = prev->tags.nopasswd;
			    if (yyvsp[0].cmndspec->tags.noexec == UNSPEC)
				yyvsp[0].cmndspec->tags.noexec = prev->tags.noexec;
			    if (yyvsp[0].cmndspec->tags.setenv == UNSPEC &&
				prev->tags.setenv != IMPLIED)
				yyvsp[0].cmndspec->tags.setenv = prev->tags.setenv;
			    if (yyvsp[0].cmndspec->tags.log_input == UNSPEC)
				yyvsp[0].cmndspec->tags.log_input = prev->tags.log_input;
			    if (yyvsp[0].cmndspec->tags.log_output == UNSPEC)
				yyvsp[0].cmndspec->tags.log_output = prev->tags.log_output;
			    if (yyvsp[0].cmndspec->tags.send_mail == UNSPEC)
				yyvsp[0].cmndspec->tags.send_mail = prev->tags.send_mail;
			    if (yyvsp[0].cmndspec->tags.follow == UNSPEC)
				yyvsp[0].cmndspec->tags.follow = prev->tags.follow;
			    if ((yyvsp[0].cmndspec->runasuserlist == NULL &&
				 yyvsp[0].cmndspec->runasgrouplist == NULL) &&
				(prev->runasuserlist != NULL ||
				 prev->runasgrouplist != NULL)) {
				yyvsp[0].cmndspec->runasuserlist = prev->runasuserlist;
				yyvsp[0].cmndspec->runasgrouplist = prev->runasgrouplist;
			    }
			    yyval.cmndspec = yyvsp[-2].cmndspec;
			}
break;
case 36:
#line 401 "gram.y"
{
			    struct cmndspec *cs = calloc(1, sizeof(*cs));
			    if (cs == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    if (yyvsp[-3].runas != NULL) {
				if (yyvsp[-3].runas->runasusers != NULL) {
				    cs->runasuserlist =
					malloc(sizeof(*cs->runasuserlist));
				    if (cs->runasuserlist == NULL) {
					free(cs);
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    HLTQ_TO_TAILQ(cs->runasuserlist,
					yyvsp[-3].runas->runasusers, entries);
				}
				if (yyvsp[-3].runas->runasgroups != NULL) {
				    cs->runasgrouplist =
					malloc(sizeof(*cs->runasgrouplist));
				    if (cs->runasgrouplist == NULL) {
					free(cs);
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    HLTQ_TO_TAILQ(cs->runasgrouplist,
					yyvsp[-3].runas->runasgroups, entries);
				}
				free(yyvsp[-3].runas);
			    }
#ifdef HAVE_SELINUX
			    cs->role = yyvsp[-2].options.role;
			    cs->type = yyvsp[-2].options.type;
#endif
#ifdef HAVE_PRIV_SET
			    cs->privs = yyvsp[-2].options.privs;
			    cs->limitprivs = yyvsp[-2].options.limitprivs;
#endif
			    cs->notbefore = yyvsp[-2].options.notbefore;
			    cs->notafter = yyvsp[-2].options.notafter;
			    cs->timeout = yyvsp[-2].options.timeout;
			    cs->tags = yyvsp[-1].tag;
			    cs->cmnd = yyvsp[0].member;
			    HLTQ_INIT(cs, entries);
			    /* sudo "ALL" implies the SETENV tag */
			    if (cs->cmnd->type == ALL && !cs->cmnd->negated &&
				cs->tags.setenv == UNSPEC)
				cs->tags.setenv = IMPLIED;
			    yyval.cmndspec = cs;
			}
break;
case 37:
#line 454 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA224, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 38:
#line 461 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA256, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 39:
#line 468 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA384, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 40:
#line 475 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA512, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 41:
#line 484 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			}
break;
case 42:
#line 487 "gram.y"
{
			    if (yyvsp[0].member->type != COMMAND) {
				sudoerserror(N_("a digest requires a path name"));
				YYERROR;
			    }
			    /* XXX - yuck */
			    ((struct sudo_command *) yyvsp[0].member->name)->digest = yyvsp[-1].digest;
			    yyval.member = yyvsp[0].member;
			}
break;
case 43:
#line 498 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 44:
#line 502 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 45:
#line 508 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 46:
#line 513 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 47:
#line 517 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 48:
#line 522 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 49:
#line 527 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 50:
#line 532 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 51:
#line 536 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 52:
#line 541 "gram.y"
{
			    yyval.runas = NULL;
			}
break;
case 53:
#line 544 "gram.y"
{
			    yyval.runas = yyvsp[-1].runas;
			}
break;
case 54:
#line 549 "gram.y"
{
			    yyval.runas = calloc(1, sizeof(struct runascontainer));
			    if (yyval.runas != NULL) {
				yyval.runas->runasusers = new_member(NULL, MYSELF);
				/* $$->runasgroups = NULL; */
				if (yyval.runas->runasusers == NULL) {
				    free(yyval.runas);
				    yyval.runas = NULL;
				}
			    }
			    if (yyval.runas == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 55:
#line 564 "gram.y"
{
			    yyval.runas = calloc(1, sizeof(struct runascontainer));
			    if (yyval.runas == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    yyval.runas->runasusers = yyvsp[0].member;
			    /* $$->runasgroups = NULL; */
			}
break;
case 56:
#line 573 "gram.y"
{
			    yyval.runas = calloc(1, sizeof(struct runascontainer));
			    if (yyval.runas == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    yyval.runas->runasusers = yyvsp[-2].member;
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 57:
#line 582 "gram.y"
{
			    yyval.runas = calloc(1, sizeof(struct runascontainer));
			    if (yyval.runas == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    /* $$->runasusers = NULL; */
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 58:
#line 591 "gram.y"
{
			    yyval.runas = calloc(1, sizeof(struct runascontainer));
			    if (yyval.runas != NULL) {
				yyval.runas->runasusers = new_member(NULL, MYSELF);
				/* $$->runasgroups = NULL; */
				if (yyval.runas->runasusers == NULL) {
				    free(yyval.runas);
				    yyval.runas = NULL;
				}
			    }
			    if (yyval.runas == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 59:
#line 608 "gram.y"
{
			    init_options(&yyval.options);
			}
break;
case 60:
#line 611 "gram.y"
{
			    yyval.options.notbefore = parse_gentime(yyvsp[0].string);
			    free(yyvsp[0].string);
			    if (yyval.options.notbefore == -1) {
				sudoerserror(N_("invalid notbefore value"));
				YYERROR;
			    }
			}
break;
case 61:
#line 619 "gram.y"
{
			    yyval.options.notafter = parse_gentime(yyvsp[0].string);
			    free(yyvsp[0].string);
			    if (yyval.options.notafter == -1) {
				sudoerserror(N_("invalid notafter value"));
				YYERROR;
			    }
			}
break;
case 62:
#line 627 "gram.y"
{
			    yyval.options.timeout = parse_timeout(yyvsp[0].string);
			    free(yyvsp[0].string);
			    if (yyval.options.timeout == -1) {
				if (errno == ERANGE)
				    sudoerserror(N_("timeout value too large"));
				else
				    sudoerserror(N_("invalid timeout value"));
				YYERROR;
			    }
			}
break;
case 63:
#line 638 "gram.y"
{
#ifdef HAVE_SELINUX
			    free(yyval.options.role);
			    yyval.options.role = yyvsp[0].string;
#endif
			}
break;
case 64:
#line 644 "gram.y"
{
#ifdef HAVE_SELINUX
			    free(yyval.options.type);
			    yyval.options.type = yyvsp[0].string;
#endif
			}
break;
case 65:
#line 650 "gram.y"
{
#ifdef HAVE_PRIV_SET
			    free(yyval.options.privs);
			    yyval.options.privs = yyvsp[0].string;
#endif
			}
break;
case 66:
#line 656 "gram.y"
{
#ifdef HAVE_PRIV_SET
			    free(yyval.options.limitprivs);
			    yyval.options.limitprivs = yyvsp[0].string;
#endif
			}
break;
case 67:
#line 664 "gram.y"
{
			    TAGS_INIT(yyval.tag);
			}
break;
case 68:
#line 667 "gram.y"
{
			    yyval.tag.nopasswd = true;
			}
break;
case 69:
#line 670 "gram.y"
{
			    yyval.tag.nopasswd = false;
			}
break;
case 70:
#line 673 "gram.y"
{
			    yyval.tag.noexec = true;
			}
break;
case 71:
#line 676 "gram.y"
{
			    yyval.tag.noexec = false;
			}
break;
case 72:
#line 679 "gram.y"
{
			    yyval.tag.setenv = true;
			}
break;
case 73:
#line 682 "gram.y"
{
			    yyval.tag.setenv = false;
			}
break;
case 74:
#line 685 "gram.y"
{
			    yyval.tag.log_input = true;
			}
break;
case 75:
#line 688 "gram.y"
{
			    yyval.tag.log_input = false;
			}
break;
case 76:
#line 691 "gram.y"
{
			    yyval.tag.log_output = true;
			}
break;
case 77:
#line 694 "gram.y"
{
			    yyval.tag.log_output = false;
			}
break;
case 78:
#line 697 "gram.y"
{
			    yyval.tag.follow = true;
			}
break;
case 79:
#line 700 "gram.y"
{
			    yyval.tag.follow = false;
			}
break;
case 80:
#line 703 "gram.y"
{
			    yyval.tag.send_mail = true;
			}
break;
case 81:
#line 706 "gram.y"
{
			    yyval.tag.send_mail = false;
			}
break;
case 82:
#line 711 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 83:
#line 718 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 84:
#line 725 "gram.y"
{
			    struct sudo_command *c = calloc(1, sizeof(*c));
			    if (c == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    c->cmnd = yyvsp[0].command.cmnd;
			    c->args = yyvsp[0].command.args;
			    yyval.member = new_member((char *)c, COMMAND);
			    if (yyval.member == NULL) {
				free(c);
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 87:
#line 746 "gram.y"
{
			    const char *s;
			    s = alias_add(&parsed_policy, yyvsp[-2].string, HOSTALIAS,
				sudoers, this_lineno, yyvsp[0].member);
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 89:
#line 758 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 92:
#line 768 "gram.y"
{
			    const char *s;
			    s = alias_add(&parsed_policy, yyvsp[-2].string, CMNDALIAS,
				sudoers, this_lineno, yyvsp[0].member);
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 94:
#line 780 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 97:
#line 790 "gram.y"
{
			    const char *s;
			    s = alias_add(&parsed_policy, yyvsp[-2].string, RUNASALIAS,
				sudoers, this_lineno, yyvsp[0].member);
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 100:
#line 805 "gram.y"
{
			    const char *s;
			    s = alias_add(&parsed_policy, yyvsp[-2].string, USERALIAS,
				sudoers, this_lineno, yyvsp[0].member);
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 102:
#line 817 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 103:
#line 823 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 104:
#line 827 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 105:
#line 833 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 106:
#line 840 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 107:
#line 847 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 108:
#line 854 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, USERGROUP);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 109:
#line 861 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 111:
#line 871 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 112:
#line 877 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 113:
#line 881 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 114:
#line 887 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 115:
#line 894 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 116:
#line 901 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
#line 2184 "gram.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (1);
yyaccept:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (0);
}
