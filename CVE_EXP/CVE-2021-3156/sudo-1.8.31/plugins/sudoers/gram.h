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
extern YYSTYPE sudoerslval;
