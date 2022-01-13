/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Interface to an Oracle database. This code was originally supplied by
Paul Kelly, but I have hacked it around for various reasons, and tried to add
some comments from my position of Oracle ignorance. */


#include "../exim.h"


/* The Oracle system headers */

#include <oratypes.h>
#include <ocidfn.h>
#include <ocikpr.h>

#define PARSE_NO_DEFER           0     /* parse straight away */
#define PARSE_V7_LNG             2
#define MAX_ITEM_BUFFER_SIZE  1024     /* largest size of a cell of data */
#define MAX_SELECT_LIST_SIZE    32     /* maximum number of columns (not rows!) */

/* Paul's comment on this was "change this to 512 for 64bit cpu", but I don't
understand why. The Oracle manual just asks for 256 bytes.

That was years ago. Jin Choi suggested (March 2007) that this change should
be made in the source, as at worst it wastes 256 bytes, and it saves people
having to discover about this for themselves as more and more systems are
64-bit. So I have changed 256 to 512. */

#define HDA_SIZE 512

/* Internal/external datatype codes */

#define NUMBER_TYPE              2
#define INT_TYPE                 3
#define FLOAT_TYPE               4
#define STRING_TYPE              5
#define ROWID_TYPE              11
#define DATE_TYPE               12

/*  ORACLE error codes used in demonstration programs */

#define VAR_NOT_IN_LIST       1007
#define NO_DATA_FOUND         1403

typedef struct Ora_Describe {
  sb4   dbsize;
  sb2   dbtype;
  sb1   buf[MAX_ITEM_BUFFER_SIZE];
  sb4   buflen;
  sb4   dsize;
  sb2   precision;
  sb2   scale;
  sb2   nullok;
} Ora_Describe;

typedef struct Ora_Define {
  ub1   buf[MAX_ITEM_BUFFER_SIZE];
  float flt_buf;
  sword int_buf;
  sb2   indp;
  ub2   col_retlen, col_retcode;
} Ora_Define;

/* Structure and anchor for caching connections. */

typedef struct oracle_connection {
  struct oracle_connection *next;
  uschar *server;
  struct cda_def *handle;
  void   *hda_mem;
} oracle_connection;

static oracle_connection *oracle_connections = NULL;





/*************************************************
*        Set up message after error              *
*************************************************/

/* Sets up a message from a local string plus whatever Oracle gives.

Arguments:
  oracle_handle   the handle of the connection
  rc              the return code
  msg             local text message
*/

static uschar *
oracle_error(struct cda_def *oracle_handle, int rc, uschar *msg)
{
uschar tmp[1024];
oerhms(oracle_handle, rc, tmp, sizeof(tmp));
return string_sprintf("ORACLE %s: %s", msg, tmp);
}



/*************************************************
*     Describe and define the select list items  *
*************************************************/

/* Figures out sizes, types, and numbers.

Arguments:
  cda        the connection
  def
  desc       descriptions put here

Returns:     number of fields
*/

static sword
describe_define(Cda_Def *cda, Ora_Define *def, Ora_Describe *desc)
{
sword col, deflen, deftyp;
static ub1 *defptr;
static sword numwidth = 8;

/* Describe the select-list items. */

for (col = 0; col < MAX_SELECT_LIST_SIZE; col++)
  {
  desc[col].buflen = MAX_ITEM_BUFFER_SIZE;

  if (odescr(cda, col + 1, &desc[col].dbsize,
             &desc[col].dbtype, &desc[col].buf[0],
             &desc[col].buflen, &desc[col].dsize,
             &desc[col].precision, &desc[col].scale,
             &desc[col].nullok) != 0)
    {
    /* Break on end of select list. */
    if (cda->rc == VAR_NOT_IN_LIST) break; else return -1;
    }

  /* Adjust sizes and types for display, handling NUMBER with scale as float. */

  if (desc[col].dbtype == NUMBER_TYPE)
    {
    desc[col].dbsize = numwidth;
    if (desc[col].scale != 0)
      {
      defptr = (ub1 *)&def[col].flt_buf;
      deflen = (sword) sizeof(float);
      deftyp = FLOAT_TYPE;
      desc[col].dbtype = FLOAT_TYPE;
      }
    else
      {
      defptr = (ub1 *)&def[col].int_buf;
      deflen = (sword) sizeof(sword);
      deftyp = INT_TYPE;
      desc[col].dbtype = INT_TYPE;
      }
    }
  else
    {
    if (desc[col].dbtype == DATE_TYPE)
        desc[col].dbsize = 9;
    if (desc[col].dbtype == ROWID_TYPE)
        desc[col].dbsize = 18;
    defptr = def[col].buf;
    deflen = desc[col].dbsize > MAX_ITEM_BUFFER_SIZE ?
      MAX_ITEM_BUFFER_SIZE : desc[col].dbsize + 1;
    deftyp = STRING_TYPE;
    desc[col].dbtype = STRING_TYPE;
    }

  /* Define an output variable */

  if (odefin(cda, col + 1,
             defptr, deflen, deftyp,
             -1, &def[col].indp, (text *) 0, -1, -1,
             &def[col].col_retlen,
             &def[col].col_retcode) != 0)
    return -1;
  }  /* Loop for each column */

return col;
}



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *
oracle_open(uschar *filename, uschar **errmsg)
{
return (void *)(1);    /* Just return something non-null */
}



/*************************************************
*               Tidy entry point                 *
*************************************************/

/* See local README for interface description. */

static void
oracle_tidy(void)
{
oracle_connection *cn;
while ((cn = oracle_connections) != NULL)
  {
  oracle_connections = cn->next;
  DEBUG(D_lookup) debug_printf("close ORACLE connection: %s\n", cn->server);
  ologof(cn->handle);
  }
}



/*************************************************
*        Internal search function                *
*************************************************/

/* This function is called from the find entry point to do the search for a
single server.

Arguments:
  query        the query string
  server       the server string
  resultptr    where to store the result
  errmsg       where to point an error message
  defer_break  TRUE if no more servers are to be tried after DEFER

The server string is of the form "host/dbname/user/password", for compatibility
with MySQL and pgsql, but at present, the dbname is not used. This string is in
a nextinlist temporary buffer, so can be overwritten.

Returns:       OK, FAIL, or DEFER
*/

static int
perform_oracle_search(uschar *query, uschar *server, uschar **resultptr,
  uschar **errmsg, BOOL *defer_break)
{
Cda_Def *cda = NULL;
struct cda_def *oracle_handle = NULL;
Ora_Describe *desc = NULL;
Ora_Define *def = NULL;
void *hda = NULL;

int i;
int yield = DEFER;
unsigned int num_fields = 0;
gstring * result = NULL;
oracle_connection *cn = NULL;
uschar *server_copy = NULL;
uschar *sdata[4];

/* Disaggregate the parameters from the server argument. The order is host,
database, user, password. We can write to the string, since it is in a
nextinlist temporary buffer. The copy of the string that is used for caching
has the password removed. This copy is also used for debugging output. */

for (i = 3; i > 0; i--)
  {
  uschar *pp = Ustrrchr(server, '/');
  if (pp == NULL)
    {
    *errmsg = string_sprintf("incomplete ORACLE server data: %s", server);
    *defer_break = TRUE;
    return DEFER;
    }
  *pp++ = 0;
  sdata[i] = pp;
  if (i == 3) server_copy = string_copy(server);  /* sans password */
  }
sdata[0] = server;   /* What's left at the start */

/* If the database is the empty string, set it NULL - the query must then
define it. */

if (sdata[1][0] == 0) sdata[1] = NULL;

/* See if we have a cached connection to the server */

for (cn = oracle_connections; cn; cn = cn->next)
  if (strcmp(cn->server, server_copy) == 0)
    {
    oracle_handle = cn->handle;
    hda = cn->hda_mem;
    break;
    }

/* If no cached connection, we must set one up */

if (!cn)
  {
  DEBUG(D_lookup) debug_printf("ORACLE new connection: host=%s database=%s "
    "user=%s\n", sdata[0], sdata[1], sdata[2]);

  /* Get store for a new connection, initialize it, and connect to the server */

   oracle_handle = store_get(sizeof(struct cda_def));
   hda = store_get(HDA_SIZE);
   memset(hda,'\0',HDA_SIZE);

  /*
   * Perform a default (blocking) login
   *
   * sdata[0] = tnsname (service name - typically host name)
   * sdata[1] = dbname - not used at present
   * sdata[2] = username
   * sdata[3] = passwd
   */

  if(olog(oracle_handle, hda, sdata[2], -1, sdata[3], -1, sdata[0], -1,
         (ub4)OCI_LM_DEF) != 0)
    {
    *errmsg = oracle_error(oracle_handle, oracle_handle->rc,
      US"connection failed");
    *defer_break = FALSE;
    goto ORACLE_EXIT_NO_VALS;
    }

  /* Add the connection to the cache */

  cn = store_get(sizeof(oracle_connection));
  cn->server = server_copy;
  cn->handle = oracle_handle;
  cn->next = oracle_connections;
  cn->hda_mem = hda;
  oracle_connections = cn;
  }

/* Else use a previously cached connection - we can write to the server string
to obliterate the password because it is in a nextinlist temporary buffer. */

else
  {
  DEBUG(D_lookup)
    debug_printf("ORACLE using cached connection for %s\n", server_copy);
  }

/* We have a connection. Open a cursor and run the query */

cda = store_get(sizeof(Cda_Def));

if (oopen(cda, oracle_handle, (text *)0, -1, -1, (text *)0, -1) != 0)
  {
  *errmsg = oracle_error(oracle_handle, cda->rc, "failed to open cursor");
  *defer_break = FALSE;
  goto ORACLE_EXIT_NO_VALS;
  }

if (oparse(cda, (text *)query, (sb4) -1,
      (sword)PARSE_NO_DEFER, (ub4)PARSE_V7_LNG) != 0)
  {
  *errmsg = oracle_error(oracle_handle, cda->rc, "query failed");
  *defer_break = FALSE;
  oclose(cda);
  goto ORACLE_EXIT_NO_VALS;
  }

/* Find the number of fields returned and sort out their types. If the number
is one, we don't add field names to the data. Otherwise we do. */

def = store_get(sizeof(Ora_Define)*MAX_SELECT_LIST_SIZE);
desc = store_get(sizeof(Ora_Describe)*MAX_SELECT_LIST_SIZE);

if ((num_fields = describe_define(cda,def,desc)) == -1)
  {
  *errmsg = oracle_error(oracle_handle, cda->rc, "describe_define failed");
  *defer_break = FALSE;
  goto ORACLE_EXIT;
  }

if (oexec(cda)!=0)
  {
  *errmsg = oracle_error(oracle_handle, cda->rc, "oexec failed");
  *defer_break = FALSE;
  goto ORACLE_EXIT;
  }

/* Get the fields and construct the result string. If there is more than one
row, we insert '\n' between them. */

while (cda->rc != NO_DATA_FOUND)  /* Loop for each row */
  {
  ofetch(cda);
  if(cda->rc == NO_DATA_FOUND) break;

  if (result) result = string_catn(result, "\n", 1);

  /* Single field - just add on the data */

  if (num_fields == 1)
    result = string_catn(result, def[0].buf, def[0].col_retlen);

  /* Multiple fields - precede by file name, removing {lead,trail}ing WS */

  else for (i = 0; i < num_fields; i++)
    {
    int slen;
    uschar *s = US desc[i].buf;

    while (*s != 0 && isspace(*s)) s++;
    slen = Ustrlen(s);
    while (slen > 0 && isspace(s[slen-1])) slen--;
    result = string_catn(result, s, slen);
    result = string_catn(result, US"=", 1);

    /* int and float type won't ever need escaping. Otherwise, quote the value
    if it contains spaces or is empty. */

    if (desc[i].dbtype != INT_TYPE && desc[i].dbtype != FLOAT_TYPE &&
       (def[i].buf[0] == 0 || strchr(def[i].buf, ' ') != NULL))
      {
      int j;
      result = string_catn(result, "\"", 1);
      for (j = 0; j < def[i].col_retlen; j++)
        {
        if (def[i].buf[j] == '\"' || def[i].buf[j] == '\\')
          result = string_catn(result, "\\", 1);
        result = string_catn(result, def[i].buf+j, 1);
        }
      result = string_catn(result, "\"", 1);
      }

    else switch(desc[i].dbtype)
      {
      case INT_TYPE:
	result = string_cat(result, string_sprintf("%d", def[i].int_buf));
	break;

      case FLOAT_TYPE:
	result = string_cat(result, string_sprintf("%f", def[i].flt_buf));
	break;

      case STRING_TYPE:
	result = string_catn(result, def[i].buf, def[i].col_retlen);
	break;

      default:
	*errmsg = string_sprintf("ORACLE: unknown field type %d", desc[i].dbtype);
	*defer_break = FALSE;
	result = NULL;
	goto ORACLE_EXIT;
      }

    result = string_catn(result, " ", 1);
    }
  }

/* If result is NULL then no data has been found and so we return FAIL.
Otherwise, we must terminate the string which has been built; string_cat()
always leaves enough room for a terminating zero. */

if (!result)
  {
  yield = FAIL;
  *errmsg = "ORACLE: no data found";
  }
else
  store_reset(result->s + result->ptr + 1);

/* Get here by goto from various error checks. */

ORACLE_EXIT:

/* Close the cursor; don't close the connection, as it is cached. */

oclose(cda);

ORACLE_EXIT_NO_VALS:

/* Non-NULL result indicates a successful result */

if (result)
  {
  *resultptr = string_from_gstring(result);
  return OK;
  }
else
  {
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  return yield;      /* FAIL or DEFER */
  }
}




/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. The handle and filename
arguments are not used. Loop through a list of servers while the query is
deferred with a retryable error. */

static int
oracle_find(void *handle, uschar *filename, uschar *query, int length,
  uschar **result, uschar **errmsg, uint *do_cache)
{
int sep = 0;
uschar *server;
uschar *list = oracle_servers;
uschar buffer[512];

do_cache = do_cache;   /* Placate picky compilers */

DEBUG(D_lookup) debug_printf("ORACLE query: %s\n", query);

while ((server = string_nextinlist(&list, &sep, buffer, sizeof(buffer))) != NULL)
  {
  BOOL defer_break;
  int rc = perform_oracle_search(query, server, result, errmsg, &defer_break);
  if (rc != DEFER || defer_break) return rc;
  }

if (oracle_servers == NULL)
  *errmsg = "no ORACLE servers defined (oracle_servers option)";

return DEFER;
}



/*************************************************
*               Quote entry point                *
*************************************************/

/* The only characters that need to be quoted (with backslash) are newline,
tab, carriage return, backspace, backslash itself, and the quote characters.
Percent and underscore are not escaped. They are only special in contexts where
they can be wild cards, and this isn't usually the case for data inserted from
messages, since that isn't likely to be treated as a pattern of any kind.

Arguments:
  s          the string to be quoted
  opt        additional option text or NULL if none

Returns:     the processed string or NULL for a bad option
*/

static uschar *
oracle_quote(uschar *s, uschar *opt)
{
register int c;
int count = 0;
uschar *t = s;
uschar *quoted;

if (opt != NULL) return NULL;    /* No options are recognized */

while ((c = *t++) != 0)
  if (strchr("\n\t\r\b\'\"\\", c) != NULL) count++;

if (count == 0) return s;
t = quoted = store_get((int)strlen(s) + count + 1);

while ((c = *s++) != 0)
  {
  if (strchr("\n\t\r\b\'\"\\", c) != NULL)
    {
    *t++ = '\\';
    switch(c)
      {
      case '\n': *t++ = 'n';
      break;
      case '\t': *t++ = 't';
      break;
      case '\r': *t++ = 'r';
      break;
      case '\b': *t++ = 'b';
      break;
      default:   *t++ = c;
      break;
      }
    }
  else *t++ = c;
  }

*t = 0;
return quoted;
}


/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
oracle_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: Oracle: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


static lookup_info _lookup_info = {
  US"oracle",                    /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  oracle_open,                   /* open function */
  NULL,                          /* check function */
  oracle_find,                   /* find function */
  NULL,                          /* no close function */
  oracle_tidy,                   /* tidy function */
  oracle_quote,                  /* quoting function */
  oracle_version_report          /* version reporting */
};

#ifdef DYNLOOKUP
#define oracle_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info oracle_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/oracle.c */
