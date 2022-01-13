/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */


/* The "type" field in each item is a set of bit flags:

  lookup_querystyle     => this is a query-style lookup,
                             else single-key (+ file) style
  lookup_absfile        => an absolute file name is required,
                             (for single-key style only)
*/

typedef struct lookup_info {
  uschar *name;                   /* e.g. "lsearch" */
  int type;                       /* query/singlekey/abs-file */
  void *(*open)(                  /* open function */
    uschar *,                     /* file name for those that have one */
    uschar **);                   /* for error message */
  BOOL (*check)(                  /* file checking function */
    void *,                       /* handle */
    uschar *,                     /* file name */
    int,                          /* modemask for file checking */
    uid_t *,                      /* owners for file checking */
    gid_t *,                      /* owngroups for file checking */
    uschar **);                   /* for error messages */
  int (*find)(                    /* find function */
    void *,                       /* handle */
    uschar *,                     /* file name or NULL */
    const uschar *,               /* key or query */
    int,                          /* length of key or query */
    uschar **,                    /* for returning answer */
    uschar **,                    /* for error message */
    uint *);                      /* cache TTL, seconds */
  void (*close)(                  /* close function */
    void *);                      /* handle */
  void (*tidy)(void);             /* tidy function */
  uschar *(*quote)(               /* quoting function */
    uschar *,                     /* string to quote */
    uschar *);                    /* additional data from quote name */
  void (*version_report)(         /* diagnostic function */
    FILE *);                      /* fh to write to */
} lookup_info;

/* This magic number is used by the following lookup_module_info structure
   for checking API compatibility. It used to be equivalent to the string"LMM3" */
#define LOOKUP_MODULE_INFO_MAGIC 0x4c4d4933
/* Version 2 adds: version_report */
/* Version 3 change: non/cache becomes TTL in seconds */

typedef struct lookup_module_info {
  uint magic;
  lookup_info **lookups;
  uint lookupcount;
} lookup_module_info;

/* End of lookupapi.h */
