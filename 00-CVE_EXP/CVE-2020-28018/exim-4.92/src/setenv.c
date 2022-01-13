/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Michael Haardt 2015
 * Copyright (c) Jeremy Harris 2015 - 2016
 * Copyright (c) The Exim Maintainers 2016 */
/* See the file NOTICE for conditions of use and distribution. */

/* This module provides (un)setenv routines for those environments
lacking them in libraries. It is #include'd by OS/os.c-foo files. */


int
setenv(const char * name, const char * val, int overwrite)
{
uschar * s;
if (Ustrchr(name, '=')) return -1;
if (overwrite || !getenv(name))
  putenv(CS string_copy_malloc(string_sprintf("%s=%s", name, val)));
return 0;
}

int
unsetenv(const char *name)
{
size_t len;
const char * end;
char ** e;
extern char ** environ;

if (!name)
  {
  errno = EINVAL;
  return -1;
  }

if (!environ)
  return 0;

for (end = name; *end != '=' && *end; ) end++;
len = end - name;
  
/* Find name in environment and move remaining variables down.
Do not early-out in case there are duplicate names. */

for (e = environ; *e; e++)
  if (strncmp(*e, name, len) == 0 && (*e)[len] == '=')
    {
    char ** sp = e;
    do *sp = sp[1]; while (*++sp);
    }

return 0;
}

/* vi: aw ai sw=2
*/
/* End of setenv.c */
