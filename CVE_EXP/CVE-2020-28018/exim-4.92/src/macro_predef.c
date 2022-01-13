/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Create a static data structure with the predefined macros, to be
included in the main Exim build */

#include "exim.h"
#include "macro_predef.h"

unsigned mp_index = 0;

/* Global dummy variables */

void fn_smtp_receive_timeout(const uschar * name, const uschar * str) {}
uschar * syslog_facility_str;

/******************************************************************************/

void
builtin_macro_create_var(const uschar * name, const uschar * val)
{
printf ("static macro_item p%d = { ", mp_index);
if (mp_index == 0)
  printf(".next=NULL,");
else
  printf(".next=&p%d,", mp_index-1);

printf(" .command_line=FALSE, .namelen=%d, .replen=%d,"
	" .name=US\"%s\", .replacement=US\"%s\" };\n",
	Ustrlen(name), Ustrlen(val), CS name, CS val);
mp_index++;
}


void
builtin_macro_create(const uschar * name)
{
builtin_macro_create_var(name, US"y");
}


/* restricted snprintf */
void
spf(uschar * buf, int len, const uschar * fmt, ...)
{
va_list ap;
va_start(ap, fmt);

while (*fmt && len > 1)
  if (*fmt == '%' && fmt[1] == 'T')
    {
    uschar * s = va_arg(ap, uschar *);
    while (*s && len-- > 1)
      *buf++ = toupper(*s++);
    fmt += 2;
    }
  else
    {
    *buf++ = *fmt++; len--;
    }
*buf = '\0';
va_end(ap);
}

void
options_from_list(optionlist * opts, unsigned nopt,
  const uschar * section, uschar * group)
{
int i;
const uschar * s;
uschar buf[64];

/* The 'previously-defined-substring' rule for macros in config file
lines is done thus for these builtin macros: we know that the table
we source from is in strict alpha order, hence the builtins portion
of the macros list is in reverse-alpha (we prepend them) - so longer
macros that have substrings are always discovered first during
expansion. */

for (i = 0; i < nopt; i++)  if (*(s = US opts[i].name) && *s != '*')
  {
  if (group)
    spf(buf, sizeof(buf), CUS"_OPT_%T_%T_%T", section, group, s);
  else
    spf(buf, sizeof(buf), CUS"_OPT_%T_%T", section, s);
  builtin_macro_create(buf);
  }
}


/******************************************************************************/


/* Create compile-time feature macros */
static void
features(void)
{
/* Probably we could work out a static initialiser for wherever
macros are stored, but this will do for now. Some names are awkward
due to conflicts with other common macros. */

#ifdef SUPPORT_CRYPTEQ
  builtin_macro_create(US"_HAVE_CRYPTEQ");
#endif
#if HAVE_ICONV
  builtin_macro_create(US"_HAVE_ICONV");
#endif
#if HAVE_IPV6
  builtin_macro_create(US"_HAVE_IPV6");
#endif
#ifdef HAVE_SETCLASSRESOURCES
  builtin_macro_create(US"_HAVE_SETCLASSRESOURCES");
#endif
#ifdef SUPPORT_PAM
  builtin_macro_create(US"_HAVE_PAM");
#endif
#ifdef EXIM_PERL
  builtin_macro_create(US"_HAVE_PERL");
#endif
#ifdef EXPAND_DLFUNC
  builtin_macro_create(US"_HAVE_DLFUNC");
#endif
#ifdef USE_TCP_WRAPPERS
  builtin_macro_create(US"_HAVE_TCPWRAPPERS");
#endif
#ifdef SUPPORT_TLS
  builtin_macro_create(US"_HAVE_TLS");
# ifdef USE_GNUTLS
  builtin_macro_create(US"_HAVE_GNUTLS");
# else
  builtin_macro_create(US"_HAVE_OPENSSL");
# endif
#endif
#ifdef SUPPORT_TRANSLATE_IP_ADDRESS
  builtin_macro_create(US"_HAVE_TRANSLATE_IP_ADDRESS");
#endif
#ifdef SUPPORT_MOVE_FROZEN_MESSAGES
  builtin_macro_create(US"_HAVE_MOVE_FROZEN_MESSAGES");
#endif
#ifdef WITH_CONTENT_SCAN
  builtin_macro_create(US"_HAVE_CONTENT_SCANNING");
#endif
#ifndef DISABLE_DKIM
  builtin_macro_create(US"_HAVE_DKIM");
#endif
#ifndef DISABLE_DNSSEC
  builtin_macro_create(US"_HAVE_DNSSEC");
#endif
#ifndef DISABLE_EVENT
  builtin_macro_create(US"_HAVE_EVENT");
#endif
#ifdef SUPPORT_I18N
  builtin_macro_create(US"_HAVE_I18N");
#endif
#ifndef DISABLE_OCSP
  builtin_macro_create(US"_HAVE_OCSP");
#endif
#ifndef DISABLE_PRDR
  builtin_macro_create(US"_HAVE_PRDR");
#endif
#ifdef SUPPORT_PROXY
  builtin_macro_create(US"_HAVE_PROXY");
#endif
#ifdef SUPPORT_SOCKS
  builtin_macro_create(US"_HAVE_SOCKS");
#endif
#ifdef TCP_FASTOPEN
  builtin_macro_create(US"_HAVE_TCP_FASTOPEN");
#endif
#ifdef EXPERIMENTAL_LMDB
  builtin_macro_create(US"_HAVE_LMDB");
#endif
#ifdef SUPPORT_SPF
  builtin_macro_create(US"_HAVE_SPF");
#endif
#ifdef EXPERIMENTAL_SRS
  builtin_macro_create(US"_HAVE_SRS");
#endif
#ifdef EXPERIMENTAL_ARC
  builtin_macro_create(US"_HAVE_ARC");
#endif
#ifdef EXPERIMENTAL_BRIGHTMAIL
  builtin_macro_create(US"_HAVE_BRIGHTMAIL");
#endif
#ifdef SUPPORT_DANE
  builtin_macro_create(US"_HAVE_DANE");
#endif
#ifdef EXPERIMENTAL_DCC
  builtin_macro_create(US"_HAVE_DCC");
#endif
#ifdef EXPERIMENTAL_DMARC
  builtin_macro_create(US"_HAVE_DMARC");
#endif
#ifdef EXPERIMENTAL_DSN_INFO
  builtin_macro_create(US"_HAVE_DSN_INFO");
#endif
#ifdef EXPERIMENTAL_REQUIRETLS
  builtin_macro_create(US"_HAVE_REQTLS");
#endif
#ifdef EXPERIMENTAL_PIPE_CONNECT
  builtin_macro_create(US"_HAVE_PIPE_CONNECT");
#endif

#ifdef LOOKUP_LSEARCH
  builtin_macro_create(US"_HAVE_LOOKUP_LSEARCH");
#endif
#ifdef LOOKUP_CDB
  builtin_macro_create(US"_HAVE_LOOKUP_CDB");
#endif
#ifdef LOOKUP_DBM
  builtin_macro_create(US"_HAVE_LOOKUP_DBM");
#endif
#ifdef LOOKUP_DNSDB
  builtin_macro_create(US"_HAVE_LOOKUP_DNSDB");
#endif
#ifdef LOOKUP_DSEARCH
  builtin_macro_create(US"_HAVE_LOOKUP_DSEARCH");
#endif
#ifdef LOOKUP_IBASE
  builtin_macro_create(US"_HAVE_LOOKUP_IBASE");
#endif
#ifdef LOOKUP_LDAP
  builtin_macro_create(US"_HAVE_LOOKUP_LDAP");
#endif
#ifdef EXPERIMENTAL_LMDB
  builtin_macro_create(US"_HAVE_LOOKUP_LMDB");
#endif
#ifdef LOOKUP_MYSQL
  builtin_macro_create(US"_HAVE_LOOKUP_MYSQL");
#endif
#ifdef LOOKUP_NIS
  builtin_macro_create(US"_HAVE_LOOKUP_NIS");
#endif
#ifdef LOOKUP_NISPLUS
  builtin_macro_create(US"_HAVE_LOOKUP_NISPLUS");
#endif
#ifdef LOOKUP_ORACLE
  builtin_macro_create(US"_HAVE_LOOKUP_ORACLE");
#endif
#ifdef LOOKUP_PASSWD
  builtin_macro_create(US"_HAVE_LOOKUP_PASSWD");
#endif
#ifdef LOOKUP_PGSQL
  builtin_macro_create(US"_HAVE_LOOKUP_PGSQL");
#endif
#ifdef LOOKUP_REDIS
  builtin_macro_create(US"_HAVE_LOOKUP_REDIS");
#endif
#ifdef LOOKUP_SQLITE
  builtin_macro_create(US"_HAVE_LOOKUP_SQLITE");
#endif
#ifdef LOOKUP_TESTDB
  builtin_macro_create(US"_HAVE_LOOKUP_TESTDB");
#endif
#ifdef LOOKUP_WHOSON
  builtin_macro_create(US"_HAVE_LOOKUP_WHOSON");
#endif

#ifdef TRANSPORT_APPENDFILE
# ifdef SUPPORT_MAILDIR
  builtin_macro_create(US"_HAVE_TRANSPORT_APPEND_MAILDIR");
# endif
# ifdef SUPPORT_MAILSTORE
  builtin_macro_create(US"_HAVE_TRANSPORT_APPEND_MAILSTORE");
# endif
# ifdef SUPPORT_MBX
  builtin_macro_create(US"_HAVE_TRANSPORT_APPEND_MBX");
# endif
#endif

#ifdef WITH_CONTENT_SCAN
features_malware();
#endif

features_crypto();
}


static void
options(void)
{
options_main();
options_routers();
options_transports();
options_auths();
options_logging();
#if defined(SUPPORT_TLS) && !defined(USE_GNUTLS)
options_tls();
#endif
}

static void
params(void)
{
#ifndef DISABLE_DKIM
params_dkim();
#endif
}


int
main(void)
{
printf("#include \"exim.h\"\n");
features();
options();
params();

printf("macro_item * macros = &p%d;\n", mp_index-1);
printf("macro_item * mlast = &p0;\n");
exit(0);
}
