/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"
#include "lf_functions.h"

/* Codes for the different kinds of lsearch that are supported */

enum {
  LSEARCH_PLAIN,        /* Literal keys */
  LSEARCH_WILD,         /* Wild card keys, expanded */
  LSEARCH_NWILD,        /* Wild card keys, not expanded */
  LSEARCH_IP            /* IP addresses and networks */
};



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description */

static void *
lsearch_open(uschar *filename, uschar **errmsg)
{
FILE *f = Ufopen(filename, "rb");
if (f == NULL)
  {
  int save_errno = errno;
  *errmsg = string_open_failed(errno, "%s for linear search", filename);
  errno = save_errno;
  return NULL;
  }
return f;
}



/*************************************************
*             Check entry point                  *
*************************************************/

static BOOL
lsearch_check(void *handle, uschar *filename, int modemask, uid_t *owners,
  gid_t *owngroups, uschar **errmsg)
{
return lf_check_file(fileno((FILE *)handle), filename, S_IFREG, modemask,
  owners, owngroups, "lsearch", errmsg) == 0;
}



/*************************************************
*  Internal function for the various lsearches   *
*************************************************/

/* See local README for interface description, plus:

Extra argument:

  type     one of the values LSEARCH_PLAIN, LSEARCH_WILD, LSEARCH_NWILD, or
           LSEARCH_IP

There is some messy logic in here to cope with very long data lines that do not
fit into the fixed sized buffer. Most of the time this will never be exercised,
but people do occasionally do weird things. */

static int
internal_lsearch_find(void *handle, uschar *filename, const uschar *keystring,
  int length, uschar **result, uschar **errmsg, int type)
{
FILE *f = (FILE *)handle;
BOOL last_was_eol = TRUE;
BOOL this_is_eol = TRUE;
int old_pool = store_pool;
void *reset_point = NULL;
uschar buffer[4096];

/* Wildcard searches may use up some store, because of expansions. We don't
want them to fill up our search store. What we do is set the pool to the main
pool and get a point to reset to later. Wildcard searches could also issue
lookups, but internal_search_find will take care of that, and the cache will be
safely stored in the search pool again. */

if(type == LSEARCH_WILD || type == LSEARCH_NWILD)
  {
  store_pool = POOL_MAIN;
  reset_point = store_get(0);
  }

filename = filename;  /* Keep picky compilers happy */
errmsg = errmsg;

rewind(f);
for (last_was_eol = TRUE;
     Ufgets(buffer, sizeof(buffer), f) != NULL;
     last_was_eol = this_is_eol)
  {
  int p = Ustrlen(buffer);
  int linekeylength;
  BOOL this_is_comment;
  gstring * yield;
  uschar *s = buffer;

  /* Check whether this the final segment of a line. If it follows an
  incomplete part-line, skip it. */

  this_is_eol = p > 0 && buffer[p-1] == '\n';
  if (!last_was_eol) continue;

  /* We now have the start of a physical line. If this is a final line segment,
  remove trailing white space. */

  if (this_is_eol)
    {
    while (p > 0 && isspace((uschar)buffer[p-1])) p--;
    buffer[p] = 0;
    }

  /* If the buffer is empty it might be (a) a complete empty line, or (b) the
  start of a line that begins with so much white space that it doesn't all fit
  in the buffer. In both cases we want to skip the entire physical line.

  If the buffer begins with # it is a comment line; if it begins with white
  space it is a logical continuation; again, we want to skip the entire
  physical line. */

  if (buffer[0] == 0 || buffer[0] == '#' || isspace(buffer[0])) continue;

  /* We assume that they key will fit in the buffer. If the key starts with ",
  read it as a quoted string. We don't use string_dequote() because that uses
  new store for the result, and we may be doing this many times in a long file.
  We know that the dequoted string must be shorter than the original, because
  we are removing the quotes, and also any escape sequences always turn two or
  more characters into one character. Therefore, we can store the new string in
  the same buffer. */

  if (*s == '\"')
    {
    uschar *t = s++;
    while (*s != 0 && *s != '\"')
      {
      if (*s == '\\') *t++ = string_interpret_escape(CUSS &s);
        else *t++ = *s;
      s++;
      }
    if (*s != 0) s++;               /* Past terminating " */
    linekeylength = t - buffer;
    }

  /* Otherwise it is terminated by a colon or white space */

  else
    {
    while (*s != 0 && *s != ':' && !isspace(*s)) s++;
    linekeylength = s - buffer;
    }

  /* The matching test depends on which kind of lsearch we are doing */

  switch(type)
    {
    /* A plain lsearch treats each key as a literal */

    case LSEARCH_PLAIN:
    if (linekeylength != length || strncmpic(buffer, keystring, length) != 0)
      continue;
    break;      /* Key matched */

    /* A wild lsearch treats each key as a possible wildcarded string; no
    expansion is done for nwildlsearch. */

    case LSEARCH_WILD:
    case LSEARCH_NWILD:
      {
      int rc;
      int save = buffer[linekeylength];
      const uschar *list = buffer;
      buffer[linekeylength] = 0;
      rc = match_isinlist(keystring,
        &list,
        UCHAR_MAX+1,              /* Single-item list */
        NULL,                     /* No anchor */
        NULL,                     /* No caching */
        MCL_STRING + ((type == LSEARCH_WILD)? 0:MCL_NOEXPAND),
        TRUE,                     /* Caseless */
        NULL);
      buffer[linekeylength] = save;
      if (rc == FAIL) continue;
      if (rc == DEFER) return DEFER;
      }

    /* The key has matched. If the search involved a regular expression, it
    might have caused numerical variables to be set. However, their values will
    be in the wrong storage pool for external use. Copying them to the standard
    pool is not feasible because of the caching of lookup results - a repeated
    lookup will not match the regular expression again. Therefore, we flatten
    all numeric variables at this point. */

    expand_nmax = -1;
    break;

    /* Compare an ip address against a list of network/ip addresses. We have to
    allow for the "*" case specially. */

    case LSEARCH_IP:
    if (linekeylength == 1 && buffer[0] == '*')
      {
      if (length != 1 || keystring[0] != '*') continue;
      }
    else if (length == 1 && keystring[0] == '*') continue;
    else
      {
      int maskoffset;
      int save = buffer[linekeylength];
      buffer[linekeylength] = 0;
      if (string_is_ip_address(buffer, &maskoffset) == 0 ||
          !host_is_in_net(keystring, buffer, maskoffset)) continue;
      buffer[linekeylength] = save;
      }
    break;      /* Key matched */
    }

  /* The key has matched. Skip spaces after the key, and allow an optional
  colon after the spaces. This is an odd specification, but it's for
  compatibility. */

  while (isspace((uschar)*s)) s++;
  if (*s == ':')
    {
    s++;
    while (isspace((uschar)*s)) s++;
    }

  /* Reset dynamic store, if we need to, and revert to the search pool */

  if (reset_point)
    {
    store_reset(reset_point);
    store_pool = old_pool;
    }

  /* Now we want to build the result string to contain the data. There can be
  two kinds of continuation: (a) the physical line may not all have fitted into
  the buffer, and (b) there may be logical continuation lines, for which we
  must convert all leading white space into a single blank.

  Initialize, and copy the first segment of data. */

  this_is_comment = FALSE;
  yield = string_get(100);
  if (*s != 0)
    yield = string_cat(yield, s);

  /* Now handle continuations */

  for (last_was_eol = this_is_eol;
       Ufgets(buffer, sizeof(buffer), f) != NULL;
       last_was_eol = this_is_eol)
    {
    s = buffer;
    p = Ustrlen(buffer);
    this_is_eol = p > 0 && buffer[p-1] == '\n';

    /* Remove trailing white space from a physical line end */

    if (this_is_eol)
      {
      while (p > 0 && isspace((uschar)buffer[p-1])) p--;
      buffer[p] = 0;
      }

    /* If this is not a physical line continuation, skip it entirely if it's
    empty or starts with #. Otherwise, break the loop if it doesn't start with
    white space. Otherwise, replace leading white space with a single blank. */

    if (last_was_eol)
      {
      this_is_comment = (this_is_comment || (buffer[0] == 0 || buffer[0] == '#'));
      if (this_is_comment) continue;
      if (!isspace((uschar)buffer[0])) break;
      while (isspace((uschar)*s)) s++;
      *(--s) = ' ';
      }
    if (this_is_comment) continue;

    /* Join a physical or logical line continuation onto the result string. */

    yield = string_cat(yield, s);
    }

  store_reset(yield->s + yield->ptr + 1);
  *result = string_from_gstring(yield);
  return OK;
  }

/* Reset dynamic store, if we need to */

if (reset_point)
  {
  store_reset(reset_point);
  store_pool = old_pool;
  }

return FAIL;
}


/*************************************************
*         Find entry point for lsearch           *
*************************************************/

/* See local README for interface description */

static int
lsearch_find(void *handle, uschar *filename, const uschar *keystring, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
do_cache = do_cache;  /* Keep picky compilers happy */
return internal_lsearch_find(handle, filename, keystring, length, result,
  errmsg, LSEARCH_PLAIN);
}



/*************************************************
*      Find entry point for wildlsearch          *
*************************************************/

/* See local README for interface description */

static int
wildlsearch_find(void *handle, uschar *filename, const uschar *keystring, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
do_cache = do_cache;  /* Keep picky compilers happy */
return internal_lsearch_find(handle, filename, keystring, length, result,
  errmsg, LSEARCH_WILD);
}



/*************************************************
*      Find entry point for nwildlsearch         *
*************************************************/

/* See local README for interface description */

static int
nwildlsearch_find(void *handle, uschar *filename, const uschar *keystring, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
do_cache = do_cache;  /* Keep picky compilers happy */
return internal_lsearch_find(handle, filename, keystring, length, result,
  errmsg, LSEARCH_NWILD);
}




/*************************************************
*      Find entry point for iplsearch            *
*************************************************/

/* See local README for interface description */

static int
iplsearch_find(void *handle, uschar *filename, const uschar *keystring, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
do_cache = do_cache;  /* Keep picky compilers happy */
if ((length == 1 && keystring[0] == '*') ||
    string_is_ip_address(keystring, NULL) != 0)
  {
  return internal_lsearch_find(handle, filename, keystring, length, result,
    errmsg, LSEARCH_IP);
  }
else
  {
  *errmsg = string_sprintf("\"%s\" is not a valid iplsearch key (an IP "
    "address, with optional CIDR mask, is wanted): "
    "in a host list, use net-iplsearch as the search type", keystring);
  return DEFER;
  }
}




/*************************************************
*              Close entry point                 *
*************************************************/

/* See local README for interface description */

static void
lsearch_close(void *handle)
{
(void)fclose((FILE *)handle);
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
lsearch_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: lsearch: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


static lookup_info iplsearch_lookup_info = {
  US"iplsearch",                 /* lookup name */
  lookup_absfile,                /* uses absolute file name */
  lsearch_open,                  /* open function */
  lsearch_check,                 /* check function */
  iplsearch_find,                /* find function */
  lsearch_close,                 /* close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  NULL                           /* no version reporting (redundant) */
};

static lookup_info lsearch_lookup_info = {
  US"lsearch",                   /* lookup name */
  lookup_absfile,                /* uses absolute file name */
  lsearch_open,                  /* open function */
  lsearch_check,                 /* check function */
  lsearch_find,                  /* find function */
  lsearch_close,                 /* close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  lsearch_version_report         /* version reporting */
};

static lookup_info nwildlsearch_lookup_info = {
  US"nwildlsearch",              /* lookup name */
  lookup_absfile,                /* uses absolute file name */
  lsearch_open,                  /* open function */
  lsearch_check,                 /* check function */
  nwildlsearch_find,             /* find function */
  lsearch_close,                 /* close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  NULL                           /* no version reporting (redundant) */
};

static lookup_info wildlsearch_lookup_info = {
  US"wildlsearch",               /* lookup name */
  lookup_absfile,                /* uses absolute file name */
  lsearch_open,                  /* open function */
  lsearch_check,                 /* check function */
  wildlsearch_find,              /* find function */
  lsearch_close,                 /* close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  NULL                           /* no version reporting (redundant) */
};

#ifdef DYNLOOKUP
#define lsearch_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &iplsearch_lookup_info,
                                       &lsearch_lookup_info,
                                       &nwildlsearch_lookup_info,
                                       &wildlsearch_lookup_info };
lookup_module_info lsearch_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 4 };

/* End of lookups/lsearch.c */
