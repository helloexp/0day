/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"

#ifdef LOOKUP_REDIS

#include "lf_functions.h"

#include <hiredis/hiredis.h>

#ifndef nele
# define nele(arr) (sizeof(arr) / sizeof(*arr))
#endif

/* Structure and anchor for caching connections. */
typedef struct redis_connection {
  struct redis_connection *next;
  uschar  *server;
  redisContext    *handle;
} redis_connection;

static redis_connection *redis_connections = NULL;


static void *
redis_open(uschar *filename, uschar **errmsg)
{
return (void *)(1);
}


void
redis_tidy(void)
{
redis_connection *cn;

/* XXX: Not sure how often this is called!
 Guess its called after every lookup which probably would mean to just
 not use the _tidy() function at all and leave with exim exiting to
 GC connections!  */

while ((cn = redis_connections))
  {
  redis_connections = cn->next;
  DEBUG(D_lookup) debug_printf("close REDIS connection: %s\n", cn->server);
  redisFree(cn->handle);
  }
}


/* This function is called from the find entry point to do the search for a
single server.

    Arguments:
      query        the query string
      server       the server string
      resultptr    where to store the result
      errmsg       where to point an error message
      defer_break  TRUE if no more servers are to be tried after DEFER
      do_cache     set false if data is changed

    The server string is of the form "host/dbnumber/password". The host can be
    host:port. This string is in a nextinlist temporary buffer, so can be
    overwritten.

    Returns:       OK, FAIL, or DEFER 
*/

static int
perform_redis_search(const uschar *command, uschar *server, uschar **resultptr,
  uschar **errmsg, BOOL *defer_break, uint *do_cache)
{
redisContext *redis_handle = NULL;        /* Keep compilers happy */
redisReply *redis_reply = NULL;
redisReply *entry = NULL;
redisReply *tentry = NULL;
redis_connection *cn;
int yield = DEFER;
int i, j;
gstring * result = NULL;
uschar *server_copy = NULL;
uschar *sdata[3];

/* Disaggregate the parameters from the server argument.
The order is host:port(socket)
We can write to the string, since it is in a nextinlist temporary buffer.
This copy is also used for debugging output.  */

memset(sdata, 0, sizeof(sdata)) /* Set all to NULL */;
for (i = 2; i > 0; i--)
  {
  uschar *pp = Ustrrchr(server, '/');

  if (!pp)
    {
    *errmsg = string_sprintf("incomplete Redis server data: %s",
      i == 2 ? server : server_copy);
    *defer_break = TRUE;
    return DEFER;
    }
  *pp++ = 0;
  sdata[i] = pp;
  if (i == 2) server_copy = string_copy(server);  /* sans password */
  }
sdata[0] = server;   /* What's left at the start */

/* If the database or password is an empty string, set it NULL */
if (sdata[1][0] == 0) sdata[1] = NULL;
if (sdata[2][0] == 0) sdata[2] = NULL;

/* See if we have a cached connection to the server */

for (cn = redis_connections; cn; cn = cn->next)
  if (Ustrcmp(cn->server, server_copy) == 0)
    {
    redis_handle = cn->handle;
    break;
    }

if (!cn)
  {
  uschar *p;
  uschar *socket = NULL;
  int port = 0;
  /* int redis_err = REDIS_OK; */

  if ((p = Ustrchr(sdata[0], '(')))
    {
    *p++ = 0;
    socket = p;
    while (*p != 0 && *p != ')') p++;
    *p = 0;
    }

  if ((p = Ustrchr(sdata[0], ':')))
    {
    *p++ = 0;
    port = Uatoi(p);
    }
  else
    port = Uatoi("6379");

  if (Ustrchr(server, '/'))
    {
    *errmsg = string_sprintf("unexpected slash in Redis server hostname: %s",
      sdata[0]);
    *defer_break = TRUE;
    return DEFER;
    }

  DEBUG(D_lookup)
    debug_printf("REDIS new connection: host=%s port=%d socket=%s database=%s\n",
      sdata[0], port, socket, sdata[1]);

  /* Get store for a new handle, initialize it, and connect to the server */
  /* XXX: Use timeouts ? */
  redis_handle =
    socket ? redisConnectUnix(CCS socket) : redisConnect(CCS server, port);
  if (!redis_handle)
    {
    *errmsg = string_sprintf("REDIS connection failed");
    *defer_break = FALSE;
    goto REDIS_EXIT;
    }

  /* Add the connection to the cache */
  cn = store_get(sizeof(redis_connection));
  cn->server = server_copy;
  cn->handle = redis_handle;
  cn->next = redis_connections;
  redis_connections = cn;
  }
else
  {
  DEBUG(D_lookup)
    debug_printf("REDIS using cached connection for %s\n", server_copy);
}

/* Authenticate if there is a password */
if(sdata[2])
  if (!(redis_reply = redisCommand(redis_handle, "AUTH %s", sdata[2])))
    {
    *errmsg = string_sprintf("REDIS Authentication failed: %s\n", redis_handle->errstr);
    *defer_break = FALSE;
    goto REDIS_EXIT;
    }

/* Select the database if there is a dbnumber passed */
if(sdata[1])
  {
  if (!(redis_reply = redisCommand(redis_handle, "SELECT %s", sdata[1])))
    {
    *errmsg = string_sprintf("REDIS: Selecting database=%s failed: %s\n", sdata[1], redis_handle->errstr);
    *defer_break = FALSE;
    goto REDIS_EXIT;
    }
  DEBUG(D_lookup) debug_printf("REDIS: Selecting database=%s\n", sdata[1]);
  }

/* split string on whitespace into argv */
  {
  uschar * argv[32];
  int i;
  const uschar * s = command;
  int siz, ptr;
  uschar c;

  while (isspace(*s)) s++;

  for (i = 0; *s && i < nele(argv); i++)
    {
    gstring * g;

    for (g = NULL; (c = *s) && !isspace(c); s++)
      if (c != '\\' || *++s)		/* backslash protects next char */
	g = string_catn(g, s, 1);
    argv[i] = string_from_gstring(g);

    DEBUG(D_lookup) debug_printf("REDIS: argv[%d] '%s'\n", i, argv[i]);
    while (isspace(*s)) s++;
    }

  /* Run the command. We use the argv form rather than plain as that parses
  into args by whitespace yet has no escaping mechanism. */

  redis_reply = redisCommandArgv(redis_handle, i, (const char **) argv, NULL);
  if (!redis_reply)
    {
    *errmsg = string_sprintf("REDIS: query failed: %s\n", redis_handle->errstr);
    *defer_break = FALSE;
    goto REDIS_EXIT;
    }
  }

switch (redis_reply->type)
  {
  case REDIS_REPLY_ERROR:
    *errmsg = string_sprintf("REDIS: lookup result failed: %s\n", redis_reply->str);

    /* trap MOVED cluster responses and follow them */
    if (Ustrncmp(redis_reply->str, "MOVED", 5) == 0)
      {
      DEBUG(D_lookup)
        debug_printf("REDIS: cluster redirect %s\n", redis_reply->str);
      /* follow redirect
      This is cheating, we simply set defer_break = FALSE to move on to
      the next server in the redis_servers list */
      *defer_break = FALSE;
      return DEFER;
      } else {
      *defer_break = TRUE;
      }
    *do_cache = 0;
    goto REDIS_EXIT;
    /* NOTREACHED */

  case REDIS_REPLY_NIL:
    DEBUG(D_lookup)
      debug_printf("REDIS: query was not one that returned any data\n");
    result = string_catn(result, US"", 1);
    *do_cache = 0;
    goto REDIS_EXIT;
    /* NOTREACHED */

  case REDIS_REPLY_INTEGER:
    result = string_cat(result, redis_reply->integer != 0 ? US"true" : US"false");
    break;

  case REDIS_REPLY_STRING:
  case REDIS_REPLY_STATUS:
    result = string_catn(result, US redis_reply->str, redis_reply->len);
    break;

  case REDIS_REPLY_ARRAY:
 
    /* NOTE: For now support 1 nested array result. If needed a limitless
    result can be parsed */

    for (i = 0; i < redis_reply->elements; i++)
      {
      entry = redis_reply->element[i];

      if (result)
	result = string_catn(result, US"\n", 1);

      switch (entry->type)
	{
	case REDIS_REPLY_INTEGER:
	  result = string_fmt_append(result, "%d", entry->integer);
	  break;
	case REDIS_REPLY_STRING:
	  result = string_catn(result, US entry->str, entry->len);
	  break;
	case REDIS_REPLY_ARRAY:
	  for (j = 0; j < entry->elements; j++)
	    {
	    tentry = entry->element[j];

	    if (result)
	      result = string_catn(result, US"\n", 1);

	    switch (tentry->type)
	      {
	      case REDIS_REPLY_INTEGER:
		result = string_fmt_append(result, "%d", tentry->integer);
		break;
	      case REDIS_REPLY_STRING:
		result = string_catn(result, US tentry->str, tentry->len);
		break;
	      case REDIS_REPLY_ARRAY:
		DEBUG(D_lookup)
		  debug_printf("REDIS: result has nesting of arrays which"
		    " is not supported. Ignoring!\n");
		break;
	      default:
		DEBUG(D_lookup) debug_printf(
			  "REDIS: result has unsupported type. Ignoring!\n");
		break;
	      }
	    }
	    break;
	  default:
	    DEBUG(D_lookup) debug_printf("REDIS: query returned unsupported type\n");
	    break;
	  }
	}
      break;
  }


if (result)
  store_reset(result->s + result->ptr + 1);
else
  {
  yield = FAIL;
  *errmsg = US"REDIS: no data found";
  }

REDIS_EXIT:

/* Free store for any result that was got; don't close the connection,
as it is cached. */

if (redis_reply) freeReplyObject(redis_reply);

/* Non-NULL result indicates a successful result */

if (result)
  {
  *resultptr = string_from_gstring(result);
  return OK;
  }
else
  {
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  /* NOTE: Required to close connection since it needs to be reopened */
  return yield;      /* FAIL or DEFER */
  }
}



/*************************************************
*               Find entry point                 *
*************************************************/
/*
 * See local README for interface description. The handle and filename
 * arguments are not used. The code to loop through a list of servers while the
 * query is deferred with a retryable error is now in a separate function that is
 * shared with other noSQL lookups.
 */

static int
redis_find(void *handle __attribute__((unused)),
  uschar *filename __attribute__((unused)),
  const uschar *command, int length, uschar **result, uschar **errmsg,
  uint *do_cache)
{
return lf_sqlperform(US"Redis", US"redis_servers", redis_servers, command,
  result, errmsg, do_cache, perform_redis_search);
}



/*************************************************
*               Quote entry point                *
*************************************************/

/* Prefix any whitespace, or backslash, with a backslash.
This is not a Redis thing but instead to let the argv splitting
we do to split on whitespace, yet provide means for getting
whitespace into an argument.

Arguments:
  s          the string to be quoted
  opt        additional option text or NULL if none

Returns:     the processed string or NULL for a bad option
*/

static uschar *
redis_quote(uschar *s, uschar *opt)
{
register int c;
int count = 0;
uschar *t = s;
uschar *quoted;

if (opt) return NULL;     /* No options recognized */

while ((c = *t++) != 0)
  if (isspace(c) || c == '\\') count++;

if (count == 0) return s;
t = quoted = store_get(Ustrlen(s) + count + 1);

while ((c = *s++) != 0)
  {
  if (isspace(c) || c == '\\') *t++ = '\\';
  *t++ = c;
  }

*t = 0;
return quoted;
}


/*************************************************
*         Version reporting entry point          *
*************************************************/
#include "../version.h"

void
redis_version_report(FILE *f)
{
fprintf(f, "Library version: REDIS: Compile: %d [%d]\n",
               HIREDIS_MAJOR, HIREDIS_MINOR);
#ifdef DYNLOOKUP
fprintf(f, "                        Exim version %s\n", EXIM_VERSION_STR);
#endif
}



/* These are the lookup_info blocks for this driver */
static lookup_info redis_lookup_info = {
  US"redis",                     /* lookup name */
  lookup_querystyle,             /* query-style lookup */
  redis_open,                    /* open function */
  NULL,                          /* no check function */
  redis_find,                    /* find function */
  NULL,                          /* no close function */
  redis_tidy,                    /* tidy function */
  redis_quote,                   /* quoting function */
  redis_version_report           /* version reporting */
};

#ifdef DYNLOOKUP
# define redis_lookup_module_info _lookup_module_info
#endif /* DYNLOOKUP */

static lookup_info *_lookup_list[] = { &redis_lookup_info };
lookup_module_info redis_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

#endif /* LOOKUP_REDIS */
/* End of lookups/redis.c */
