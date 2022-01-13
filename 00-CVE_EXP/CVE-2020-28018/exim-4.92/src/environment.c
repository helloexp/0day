/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Heiko Schlittermann 2016
 * hs@schlittermann.de
 * See the file NOTICE for conditions of use and distribution.
 */

#include "exim.h"

extern char **environ;

/* The cleanup_environment() function is used during the startup phase
of the Exim process, right after reading the configurations main
part, before any expansions take place. It retains the environment
variables we trust (via the keep_environment option) and allows to
set additional variables (via add_environment).

Returns:    TRUE if successful
            FALSE otherwise
*/

BOOL
cleanup_environment()
{
if (!keep_environment || *keep_environment == '\0')
  {
  /* From: https://github.com/dovecot/core/blob/master/src/lib/env-util.c#L55
  Try to clear the environment.
  a) environ = NULL crashes on OS X.
  b) *environ = NULL doesn't work on FreeBSD 7.0.
  c) environ = emptyenv doesn't work on Haiku OS
  d) environ = calloc() should work everywhere */

  if (environ) *environ = NULL;

  }
else if (Ustrcmp(keep_environment, "*") != 0)
  {
  uschar **p;
  if (environ) for (p = USS environ; *p; /* see below */)
    {
    /* It's considered broken if we do not find the '=', according to
    Florian Weimer. For now we ignore such strings. unsetenv() would complain,
    getenv() would complain. */
    uschar * eqp = Ustrchr(*p, '=');

    if (eqp)
      {
      uschar * name = string_copyn(*p, eqp - *p);

      if (OK != match_isinlist(name, CUSS &keep_environment,
          0, NULL, NULL, MCL_NOEXPAND, FALSE, NULL))
        if (os_unsetenv(name) < 0) return FALSE;
        else p = USS environ; /* RESTART from the beginning */
      else p++;
      store_reset(name);
      }
    }
  }
if (add_environment)
  {
    uschar * p;
    int sep = 0;
    const uschar * envlist = add_environment;

    while ((p = string_nextinlist(&envlist, &sep, NULL, 0))) putenv(CS p);
  }

  return TRUE;
}
