/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "lf_functions.h"



/*************************************************
*    Call SQL server(s) to run an actual query   *
*************************************************/

/* All the SQL lookups are of the same form, with a list of servers to try
until one can be accessed. It is now also possible to provide the server data
as part of the query. This function manages server selection and looping; each
lookup has its own function for actually performing the lookup.

Arguments:
  name           the lookup name, e.g. "MySQL"
  optionname     the name of the servers option, e.g. "mysql_servers"
  optserverlist  the value of the servers option
  query          the query
  result         where to pass back the result
  errmsg         where to pass back an error message
  do_cache       to be set zero if data is changed
  func           the lookup function to call

Returns:         the return from the lookup function, or DEFER
*/

int
lf_sqlperform(const uschar *name, const uschar *optionname,
  const uschar *optserverlist, const uschar *query,
  uschar **result, uschar **errmsg, uint *do_cache,
  int(*fn)(const uschar *, uschar *, uschar **, uschar **, BOOL *, uint *))
{
int sep, rc;
uschar *server;
const uschar *serverlist;
uschar buffer[512];
BOOL defer_break = FALSE;

DEBUG(D_lookup) debug_printf("%s query: %s\n", name, query);

/* Handle queries that do not have server information at the start. */

if (Ustrncmp(query, "servers", 7) != 0)
  {
  sep = 0;
  serverlist = optserverlist;
  while ((server = string_nextinlist(&serverlist, &sep, buffer,
          sizeof(buffer))) != NULL)
    {
    rc = (*fn)(query, server, result, errmsg, &defer_break, do_cache);
    if (rc != DEFER || defer_break) return rc;
    }
  if (optserverlist == NULL)
    *errmsg = string_sprintf("no %s servers defined (%s option)", name,
      optionname);
  }

/* Handle queries that do have server information at the start. */

else
  {
  int qsep;
  const uschar *s, *ss;
  const uschar *qserverlist;
  uschar *qserver;
  uschar qbuffer[512];

  s = query + 7;
  while (isspace(*s)) s++;
  if (*s++ != '=')
    {
    *errmsg = string_sprintf("missing = after \"servers\" in %s lookup", name);
    return DEFER;
    }
  while (isspace(*s)) s++;

  ss = Ustrchr(s, ';');
  if (ss == NULL)
    {
    *errmsg = string_sprintf("missing ; after \"servers=\" in %s lookup",
      name);
    return DEFER;
    }

  if (ss == s)
    {
    *errmsg = string_sprintf("\"servers=\" defines no servers in \"%s\"",
      query);
    return DEFER;
    }

  qserverlist = string_sprintf("%.*s", (int)(ss - s), s);
  qsep = 0;

  while ((qserver = string_nextinlist(&qserverlist, &qsep, qbuffer,
           sizeof(qbuffer))) != NULL)
    {
    if (Ustrchr(qserver, '/') != NULL)
      server = qserver;
    else
      {
      int len = Ustrlen(qserver);

      sep = 0;
      serverlist = optserverlist;
      while ((server = string_nextinlist(&serverlist, &sep, buffer,
              sizeof(buffer))) != NULL)
        {
        if (Ustrncmp(server, qserver, len) == 0 && server[len] == '/')
          break;
        }

      if (server == NULL)
        {
        *errmsg = string_sprintf("%s server \"%s\" not found in %s", name,
          qserver, optionname);
        return DEFER;
        }
      }

    rc = (*fn)(ss+1, server, result, errmsg, &defer_break, do_cache);
    if (rc != DEFER || defer_break) return rc;
    }
  }

return DEFER;
}

/* End of lf_sqlperform.c */
