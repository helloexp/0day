/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* The code in this module was contributed by Ard Biesheuvel. */

#include "../exim.h"
#include "lf_functions.h"

#include <ibase.h>              /* The system header */

/* Structure and anchor for caching connections. */

typedef struct ibase_connection {
    struct ibase_connection *next;
    uschar *server;
    isc_db_handle dbh;
    isc_tr_handle transh;
} ibase_connection;

static ibase_connection *ibase_connections = NULL;



/*************************************************
*              Open entry point                  *
*************************************************/

/* See local README for interface description. */

static void *ibase_open(uschar * filename, uschar ** errmsg)
{
    return (void *) (1);        /* Just return something non-null */
}



/*************************************************
*               Tidy entry point                 *
*************************************************/

/* See local README for interface description. */

static void ibase_tidy(void)
{
    ibase_connection *cn;
    ISC_STATUS status[20];

    while ((cn = ibase_connections) != NULL) {
        ibase_connections = cn->next;
        DEBUG(D_lookup) debug_printf("close Interbase connection: %s\n",
                                     cn->server);
        isc_commit_transaction(status, &cn->transh);
        isc_detach_database(status, &cn->dbh);
    }
}

static int fetch_field(char *buffer, int buffer_size, XSQLVAR * var)
{
    if (buffer_size < var->sqllen)
        return 0;

    switch (var->sqltype & ~1) {
    case SQL_VARYING:
        strncpy(buffer, &var->sqldata[2], *(short *) var->sqldata);
        return *(short *) var->sqldata;
    case SQL_TEXT:
        strncpy(buffer, var->sqldata, var->sqllen);
        return var->sqllen;
    case SQL_SHORT:
        return sprintf(buffer, "%d", *(short *) var->sqldata);
    case SQL_LONG:
        return sprintf(buffer, "%ld", *(ISC_LONG *) var->sqldata);
#ifdef SQL_INT64
    case SQL_INT64:
        return sprintf(buffer, "%lld", *(ISC_INT64 *) var->sqldata);
#endif
    default:
        /* not implemented */
        return 0;
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

The server string is of the form "host:dbname|user|password". The host can be
host:port. This string is in a nextinlist temporary buffer, so can be
overwritten.

Returns:       OK, FAIL, or DEFER
*/

static int
perform_ibase_search(uschar * query, uschar * server, uschar ** resultptr,
                     uschar ** errmsg, BOOL * defer_break)
{
isc_stmt_handle stmth = NULL;
XSQLDA *out_sqlda;
XSQLVAR *var;

char buffer[256];
ISC_STATUS status[20], *statusp = status;

gstring * result;
int i;
int yield = DEFER;
ibase_connection *cn;
uschar *server_copy = NULL;
uschar *sdata[3];

/* Disaggregate the parameters from the server argument. The order is host,
database, user, password. We can write to the string, since it is in a
nextinlist temporary buffer. The copy of the string that is used for caching
has the password removed. This copy is also used for debugging output. */

for (i = 2; i > 0; i--)
  {
  uschar *pp = Ustrrchr(server, '|');

  if (pp == NULL)
    {
    *errmsg = string_sprintf("incomplete Interbase server data: %s",
		       (i == 3) ? server : server_copy);
    *defer_break = TRUE;
    return DEFER;
    }
  *pp++ = 0;
  sdata[i] = pp;
  if (i == 2)
      server_copy = string_copy(server);   /* sans password */
  }
sdata[0] = server;          /* What's left at the start */

/* See if we have a cached connection to the server */

for (cn = ibase_connections; cn != NULL; cn = cn->next)
  if (Ustrcmp(cn->server, server_copy) == 0)
    break;

/* Use a previously cached connection ? */

if (cn)
  {
  static char db_info_options[] = { isc_info_base_level };

  /* test if the connection is alive */
  if (isc_database_info(status, &cn->dbh, sizeof(db_info_options),
	db_info_options, sizeof(buffer), buffer))
    {
    /* error occurred: assume connection is down */
    DEBUG(D_lookup)
	debug_printf
	("Interbase cleaning up cached connection: %s\n",
	 cn->server);
    isc_detach_database(status, &cn->dbh);
    }
  else
    {
    DEBUG(D_lookup) debug_printf("Interbase using cached connection for %s\n",
		     server_copy);
    }
  }
else
  {
  cn = store_get(sizeof(ibase_connection));
  cn->server = server_copy;
  cn->dbh = NULL;
  cn->transh = NULL;
  cn->next = ibase_connections;
  ibase_connections = cn;
  }

/* If no cached connection, we must set one up. */

if (cn->dbh == NULL || cn->transh == NULL)
  {
  char *dpb, *p;
  short dpb_length;
  static char trans_options[] =
      { isc_tpb_version3, isc_tpb_read, isc_tpb_read_committed,
      isc_tpb_rec_version
  };

  /* Construct the database parameter buffer. */
  dpb = buffer;
  *dpb++ = isc_dpb_version1;
  *dpb++ = isc_dpb_user_name;
  *dpb++ = strlen(sdata[1]);
  for (p = sdata[1]; *p;)
      *dpb++ = *p++;
  *dpb++ = isc_dpb_password;
  *dpb++ = strlen(sdata[2]);
  for (p = sdata[2]; *p;)
      *dpb++ = *p++;
  dpb_length = dpb - buffer;

  DEBUG(D_lookup)
      debug_printf("new Interbase connection: database=%s user=%s\n",
		   sdata[0], sdata[1]);

  /* Connect to the database */
  if (isc_attach_database
      (status, 0, sdata[0], &cn->dbh, dpb_length, buffer))
    {
    isc_interprete(buffer, &statusp);
    *errmsg =
	string_sprintf("Interbase attach() failed: %s", buffer);
    *defer_break = FALSE;
    goto IBASE_EXIT;
    }

  /* Now start a read-only read-committed transaction */
  if (isc_start_transaction
      (status, &cn->transh, 1, &cn->dbh, sizeof(trans_options),
       trans_options))
    {
    isc_interprete(buffer, &statusp);
    isc_detach_database(status, &cn->dbh);
    *errmsg =
	string_sprintf("Interbase start_transaction() failed: %s",
		       buffer);
    *defer_break = FALSE;
    goto IBASE_EXIT;
    }
  }

/* Run the query */
if (isc_dsql_allocate_statement(status, &cn->dbh, &stmth))
  {
  isc_interprete(buffer, &statusp);
  *errmsg =
      string_sprintf("Interbase alloc_statement() failed: %s",
		     buffer);
  *defer_break = FALSE;
  goto IBASE_EXIT;
  }

out_sqlda = store_get(XSQLDA_LENGTH(1));
out_sqlda->version = SQLDA_VERSION1;
out_sqlda->sqln = 1;

if (isc_dsql_prepare
    (status, &cn->transh, &stmth, 0, query, 1, out_sqlda))
  {
  isc_interprete(buffer, &statusp);
  store_reset(out_sqlda);
  out_sqlda = NULL;
  *errmsg =
      string_sprintf("Interbase prepare_statement() failed: %s",
		     buffer);
  *defer_break = FALSE;
  goto IBASE_EXIT;
  }

/* re-allocate the output structure if there's more than one field */
if (out_sqlda->sqln < out_sqlda->sqld)
  {
  XSQLDA *new_sqlda = store_get(XSQLDA_LENGTH(out_sqlda->sqld));
  if (isc_dsql_describe
      (status, &stmth, out_sqlda->version, new_sqlda))
    {
    isc_interprete(buffer, &statusp);
    isc_dsql_free_statement(status, &stmth, DSQL_drop);
    store_reset(out_sqlda);
    out_sqlda = NULL;
    *errmsg = string_sprintf("Interbase describe_statement() failed: %s",
		       buffer);
    *defer_break = FALSE;
    goto IBASE_EXIT;
    }
  out_sqlda = new_sqlda;
  }

/* allocate storage for every returned field */
for (i = 0, var = out_sqlda->sqlvar; i < out_sqlda->sqld; i++, var++)
  {
  switch (var->sqltype & ~1)
    {
    case SQL_VARYING:
	var->sqldata = CS store_get(sizeof(char) * var->sqllen + 2);
	break;
    case SQL_TEXT:
	var->sqldata = CS store_get(sizeof(char) * var->sqllen);
	break;
    case SQL_SHORT:
	var->sqldata = CS  store_get(sizeof(short));
	break;
    case SQL_LONG:
	var->sqldata = CS  store_get(sizeof(ISC_LONG));
	break;
#ifdef SQL_INT64
    case SQL_INT64:
	var->sqldata = CS  store_get(sizeof(ISC_INT64));
	break;
#endif
    case SQL_FLOAT:
	var->sqldata = CS  store_get(sizeof(float));
	break;
    case SQL_DOUBLE:
	var->sqldata = CS  store_get(sizeof(double));
	break;
#ifdef SQL_TIMESTAMP
    case SQL_DATE:
	var->sqldata = CS  store_get(sizeof(ISC_QUAD));
	break;
#else
    case SQL_TIMESTAMP:
	var->sqldata = CS  store_get(sizeof(ISC_TIMESTAMP));
	break;
    case SQL_TYPE_DATE:
	var->sqldata = CS  store_get(sizeof(ISC_DATE));
	break;
    case SQL_TYPE_TIME:
	var->sqldata = CS  store_get(sizeof(ISC_TIME));
	break;
  #endif
    }
  if (var->sqltype & 1)
    var->sqlind = (short *) store_get(sizeof(short));
  }

/* finally, we're ready to execute the statement */
if (isc_dsql_execute
    (status, &cn->transh, &stmth, out_sqlda->version, NULL))
  {
  isc_interprete(buffer, &statusp);
  *errmsg = string_sprintf("Interbase describe_statement() failed: %s",
		     buffer);
  isc_dsql_free_statement(status, &stmth, DSQL_drop);
  *defer_break = FALSE;
  goto IBASE_EXIT;
  }

while (isc_dsql_fetch(status, &stmth, out_sqlda->version, out_sqlda) != 100L)
  {
  /* check if an error occurred */
  if (status[0] & status[1])
    {
    isc_interprete(buffer, &statusp);
    *errmsg =
	string_sprintf("Interbase fetch() failed: %s", buffer);
    isc_dsql_free_statement(status, &stmth, DSQL_drop);
    *defer_break = FALSE;
    goto IBASE_EXIT;
    }

  if (result)
    result = string_catn(result, US "\n", 1);

  /* Find the number of fields returned. If this is one, we don't add field
     names to the data. Otherwise we do. */
  if (out_sqlda->sqld == 1)
    {
    if (out_sqlda->sqlvar[0].sqlind == NULL || *out_sqlda->sqlvar[0].sqlind != -1)     /* NULL value yields nothing */
      result = string_catn(result, US buffer,
		       fetch_field(buffer, sizeof(buffer),
				   &out_sqlda->sqlvar[0]));
    }

  else
    for (i = 0; i < out_sqlda->sqld; i++)
      {
      int len = fetch_field(buffer, sizeof(buffer), &out_sqlda->sqlvar[i]);

      result = string_catn(result, US out_sqlda->sqlvar[i].aliasname,
		     out_sqlda->sqlvar[i].aliasname_length);
      result = string_catn(result, US "=", 1);

      /* Quote the value if it contains spaces or is empty */

      if (*out_sqlda->sqlvar[i].sqlind == -1)       /* NULL value */
	result = string_catn(result, US "\"\"", 2);

      else if (buffer[0] == 0 || Ustrchr(buffer, ' ') != NULL)
	{
	int j;

	result = string_catn(result, US "\"", 1);
	for (j = 0; j < len; j++)
	  {
	  if (buffer[j] == '\"' || buffer[j] == '\\')
	      result = string_cat(result, US "\\", 1);
	  result = string_cat(result, US buffer + j, 1);
	  }
	result = string_catn(result, US "\"", 1);
	}
      else
	result = string_catn(result, US buffer, len);
      result = string_catn(result, US " ", 1);
      }
  }

/* If result is NULL then no data has been found and so we return FAIL.
Otherwise, we must terminate the string which has been built; string_cat()
always leaves enough room for a terminating zero. */

if (!result)
  {
  yield = FAIL;
  *errmsg = US "Interbase: no data found";
  }
else
  store_reset(result->s + result->ptr + 1);


/* Get here by goto from various error checks. */

IBASE_EXIT:

if (stmth)
  isc_dsql_free_statement(status, &stmth, DSQL_drop);

/* Non-NULL result indicates a successful result */

if (result)
  {
  *resultptr = string_from_gstring(result);
  return OK;
  }
else
  {
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  return yield;           /* FAIL or DEFER */
  }
}




/*************************************************
*               Find entry point                 *
*************************************************/

/* See local README for interface description. The handle and filename
arguments are not used. Loop through a list of servers while the query is
deferred with a retryable error. */

static int
ibase_find(void *handle, uschar * filename, uschar * query, int length,
           uschar ** result, uschar ** errmsg, uint *do_cache)
{
    int sep = 0;
    uschar *server;
    uschar *list = ibase_servers;
    uschar buffer[512];

    /* Keep picky compilers happy */
    do_cache = do_cache;

    DEBUG(D_lookup) debug_printf("Interbase query: %s\n", query);

    while ((server =
            string_nextinlist(&list, &sep, buffer,
                              sizeof(buffer))) != NULL) {
        BOOL defer_break = FALSE;
        int rc = perform_ibase_search(query, server, result, errmsg,
                                      &defer_break);
        if (rc != DEFER || defer_break)
            return rc;
    }

    if (ibase_servers == NULL)
        *errmsg = US "no Interbase servers defined (ibase_servers option)";

    return DEFER;
}



/*************************************************
*               Quote entry point                *
*************************************************/

/* The only characters that need to be quoted (with backslash) are newline,
tab, carriage return, backspace, backslash itself, and the quote characters.
Percent, and underscore and not escaped. They are only special in contexts
where they can be wild cards, and this isn't usually the case for data inserted
from messages, since that isn't likely to be treated as a pattern of any kind.
Sadly, MySQL doesn't seem to behave like other programs. If you use something
like "where id="ab\%cd" it does not treat the string as "ab%cd". So you really
can't quote "on spec".

Arguments:
  s          the string to be quoted
  opt        additional option text or NULL if none

Returns:     the processed string or NULL for a bad option
*/

static uschar *ibase_quote(uschar * s, uschar * opt)
{
    register int c;
    int count = 0;
    uschar *t = s;
    uschar *quoted;

    if (opt != NULL)
        return NULL;            /* No options recognized */

    while ((c = *t++) != 0)
        if (Ustrchr("\n\t\r\b\'\"\\", c) != NULL)
            count++;

    if (count == 0)
        return s;
    t = quoted = store_get(Ustrlen(s) + count + 1);

    while ((c = *s++) != 0) {
        if (Ustrchr("'", c) != NULL) {
            *t++ = '\'';
            *t++ = '\'';
/*    switch(c)
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
      }*/
        } else
            *t++ = c;
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
ibase_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: ibase: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


static lookup_info _lookup_info = {
  US"ibase",                     /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  ibase_open,                    /* open function */
  NULL,                          /* no check function */
  ibase_find,                    /* find function */
  NULL,                          /* no close function */
  ibase_tidy,                    /* tidy function */
  ibase_quote,                   /* quoting function */
  ibase_version_report           /* version reporting */
};

#ifdef DYNLOOKUP
#define ibase_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &_lookup_info };
lookup_module_info ibase_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/ibase.c */
