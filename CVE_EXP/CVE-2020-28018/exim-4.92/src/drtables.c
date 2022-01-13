/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "exim.h"

#include <string.h>

/* This module contains tables that define the lookup methods and drivers
that are actually included in the binary. Its contents are controlled by
various macros in config.h that ultimately come from Local/Makefile. They are
all described in src/EDITME. */


lookup_info **lookup_list;
int lookup_list_count = 0;

/* Table of information about all possible authentication mechanisms. All
entries are always present if any mechanism is declared, but the functions are
set to NULL for those that are not compiled into the binary. */

#ifdef AUTH_CRAM_MD5
#include "auths/cram_md5.h"
#endif

#ifdef AUTH_CYRUS_SASL
#include "auths/cyrus_sasl.h"
#endif

#ifdef AUTH_DOVECOT
#include "auths/dovecot.h"
#endif

#ifdef AUTH_GSASL
#include "auths/gsasl_exim.h"
#endif

#ifdef AUTH_HEIMDAL_GSSAPI
#include "auths/heimdal_gssapi.h"
#endif

#ifdef AUTH_PLAINTEXT
#include "auths/plaintext.h"
#endif

#ifdef AUTH_SPA
#include "auths/spa.h"
#endif

#ifdef AUTH_TLS
#include "auths/tls.h"
#endif

auth_info auths_available[] = {

/* Checking by an expansion condition on plain text */

#ifdef AUTH_CRAM_MD5
  {
  .driver_name =	US"cram_md5",                              /* lookup name */
  .options =		auth_cram_md5_options,
  .options_count =	&auth_cram_md5_options_count,
  .options_block =	&auth_cram_md5_option_defaults,
  .options_len =	sizeof(auth_cram_md5_options_block),
  .init =		auth_cram_md5_init,
  .servercode =		auth_cram_md5_server,
  .clientcode =		auth_cram_md5_client,
  .version_report =	NULL
  },
#endif

#ifdef AUTH_CYRUS_SASL
  {
  .driver_name =	US"cyrus_sasl",
  .options =		auth_cyrus_sasl_options,
  .options_count =	&auth_cyrus_sasl_options_count,
  .options_block =	&auth_cyrus_sasl_option_defaults,
  .options_len =	sizeof(auth_cyrus_sasl_options_block),
  .init =		auth_cyrus_sasl_init,
  .servercode =		auth_cyrus_sasl_server,
  .clientcode =		NULL,
  .version_report =	auth_cyrus_sasl_version_report
  },
#endif

#ifdef AUTH_DOVECOT
  {
  .driver_name =	US"dovecot",
  .options =		auth_dovecot_options,
  .options_count =	&auth_dovecot_options_count,
  .options_block =	&auth_dovecot_option_defaults,
  .options_len =	sizeof(auth_dovecot_options_block),
  .init =		auth_dovecot_init,
  .servercode =		auth_dovecot_server,
  .clientcode =		NULL,
  .version_report =	NULL
  },
#endif

#ifdef AUTH_GSASL
  {
  .driver_name =	US"gsasl",
  .options =		auth_gsasl_options,
  .options_count =	&auth_gsasl_options_count,
  .options_block =	&auth_gsasl_option_defaults,
  .options_len =	sizeof(auth_gsasl_options_block),
  .init =		auth_gsasl_init,
  .servercode =		auth_gsasl_server,
  .clientcode =		NULL,
  .version_report =	auth_gsasl_version_report
  },
#endif

#ifdef AUTH_HEIMDAL_GSSAPI
  {
  .driver_name =	US"heimdal_gssapi",
  .options =		auth_heimdal_gssapi_options,
  .options_count =	&auth_heimdal_gssapi_options_count,
  .options_block =	&auth_heimdal_gssapi_option_defaults,
  .options_len =	sizeof(auth_heimdal_gssapi_options_block),
  .init =		auth_heimdal_gssapi_init,
  .servercode =		auth_heimdal_gssapi_server,
  .clientcode =		NULL,
  .version_report =	auth_heimdal_gssapi_version_report
  },
#endif

#ifdef AUTH_PLAINTEXT
  {
  .driver_name =	US"plaintext",
  .options =		auth_plaintext_options,
  .options_count =	&auth_plaintext_options_count,
  .options_block =	&auth_plaintext_option_defaults,
  .options_len =	sizeof(auth_plaintext_options_block),
  .init =		auth_plaintext_init,
  .servercode =		auth_plaintext_server,
  .clientcode =		auth_plaintext_client,
  .version_report =	NULL
  },
#endif

#ifdef AUTH_SPA
  {
  .driver_name =	US"spa",
  .options =		auth_spa_options,
  .options_count =	&auth_spa_options_count,
  .options_block =	&auth_spa_option_defaults,
  .options_len =	sizeof(auth_spa_options_block),
  .init =		auth_spa_init,
  .servercode =		auth_spa_server,
  .clientcode =		auth_spa_client,
  .version_report =	NULL
  },
#endif

#ifdef AUTH_TLS
  {
  .driver_name =	US"tls",
  .options =		auth_tls_options,
  .options_count =	&auth_tls_options_count,
  .options_block =	&auth_tls_option_defaults,
  .options_len =	sizeof(auth_tls_options_block),
  .init =		auth_tls_init,
  .servercode =		auth_tls_server,
  .clientcode =		NULL,
  .version_report =	NULL
  },
#endif

  { .driver_name = US"" }		/* end marker */
};

void
auth_show_supported(FILE * f)
{
auth_info * ai;
fprintf(f, "Authenticators:");
for (ai = auths_available; ai->driver_name[0]; ai++)
       	fprintf(f, " %s", ai->driver_name);
fprintf(f, "\n");
}


/* Tables of information about which routers and transports are included in the
exim binary. */

/* Pull in the necessary header files */

#include "routers/rf_functions.h"

#ifdef ROUTER_ACCEPT
#include "routers/accept.h"
#endif

#ifdef ROUTER_DNSLOOKUP
#include "routers/dnslookup.h"
#endif

#ifdef ROUTER_MANUALROUTE
#include "routers/manualroute.h"
#endif

#ifdef ROUTER_IPLITERAL
#include "routers/ipliteral.h"
#endif

#ifdef ROUTER_IPLOOKUP
#include "routers/iplookup.h"
#endif

#ifdef ROUTER_QUERYPROGRAM
#include "routers/queryprogram.h"
#endif

#ifdef ROUTER_REDIRECT
#include "routers/redirect.h"
#endif

#ifdef TRANSPORT_APPENDFILE
#include "transports/appendfile.h"
#endif

#ifdef TRANSPORT_AUTOREPLY
#include "transports/autoreply.h"
#endif

#ifdef TRANSPORT_LMTP
#include "transports/lmtp.h"
#endif

#ifdef TRANSPORT_PIPE
#include "transports/pipe.h"
#endif

#ifdef EXPERIMENTAL_QUEUEFILE
#include "transports/queuefile.h"
#endif

#ifdef TRANSPORT_SMTP
#include "transports/smtp.h"
#endif


/* Now set up the structures, terminated by an entry with a null name. */

router_info routers_available[] = {
#ifdef ROUTER_ACCEPT
  {
  .driver_name =	US"accept",
  .options =		accept_router_options,
  .options_count =	&accept_router_options_count,
  .options_block =	&accept_router_option_defaults,
  .options_len =	sizeof(accept_router_options_block),
  .init =		accept_router_init,
  .code =		accept_router_entry,
  .tidyup =		NULL,     /* no tidyup entry */
  .ri_flags =		ri_yestransport
  },
#endif
#ifdef ROUTER_DNSLOOKUP
  {
  .driver_name =	US"dnslookup",
  .options =		dnslookup_router_options,
  .options_count =	&dnslookup_router_options_count,
  .options_block =	&dnslookup_router_option_defaults,
  .options_len =	sizeof(dnslookup_router_options_block),
  .init =		dnslookup_router_init,
  .code =		dnslookup_router_entry,
  .tidyup =		NULL,     /* no tidyup entry */
  .ri_flags =		ri_yestransport
  },
#endif
#ifdef ROUTER_IPLITERAL
  {
  .driver_name =	US"ipliteral",
  .options =		ipliteral_router_options,
  .options_count =	&ipliteral_router_options_count,
  .options_block =	&ipliteral_router_option_defaults,
  .options_len =	sizeof(ipliteral_router_options_block),
  .init =		ipliteral_router_init,
  .code =		ipliteral_router_entry,
  .tidyup =		NULL,     /* no tidyup entry */
  .ri_flags =		ri_yestransport
  },
#endif
#ifdef ROUTER_IPLOOKUP
  {
  .driver_name =	US"iplookup",
  .options =		iplookup_router_options,
  .options_count =	&iplookup_router_options_count,
  .options_block =	&iplookup_router_option_defaults,
  .options_len =	sizeof(iplookup_router_options_block),
  .init =		iplookup_router_init,
  .code =		iplookup_router_entry,
  .tidyup =		NULL,     /* no tidyup entry */
  .ri_flags =		ri_notransport
  },
#endif
#ifdef ROUTER_MANUALROUTE
  {
  .driver_name =	US"manualroute",
  .options =		manualroute_router_options,
  .options_count =	&manualroute_router_options_count,
  .options_block =	&manualroute_router_option_defaults,
  .options_len =	sizeof(manualroute_router_options_block),
  .init =		manualroute_router_init,
  .code =		manualroute_router_entry,
  .tidyup =		NULL,     /* no tidyup entry */
  .ri_flags =		0
  },
#endif
#ifdef ROUTER_QUERYPROGRAM
  {
  .driver_name =	US"queryprogram",
  .options =		queryprogram_router_options,
  .options_count =	&queryprogram_router_options_count,
  .options_block =	&queryprogram_router_option_defaults,
  .options_len =	sizeof(queryprogram_router_options_block),
  .init =		queryprogram_router_init,
  .code =		queryprogram_router_entry,
  .tidyup =		NULL,     /* no tidyup entry */
  .ri_flags =		0
  },
#endif
#ifdef ROUTER_REDIRECT
  {
  .driver_name =	US"redirect",
  .options =		redirect_router_options,
  .options_count =	&redirect_router_options_count,
  .options_block =	&redirect_router_option_defaults,
  .options_len =	sizeof(redirect_router_options_block),
  .init =		redirect_router_init,
  .code =		redirect_router_entry,
  .tidyup =		NULL,     /* no tidyup entry */
  .ri_flags =		ri_notransport
  },
#endif
  { US"" }
};


void
route_show_supported(FILE * f)
{
router_info * rr;
fprintf(f, "Routers:");
for (rr = routers_available; rr->driver_name[0]; rr++)
       	fprintf(f, " %s", rr->driver_name);
fprintf(f, "\n");
}




transport_info transports_available[] = {
#ifdef TRANSPORT_APPENDFILE
  {
  .driver_name =	US"appendfile",
  .options =		appendfile_transport_options,
  .options_count =	&appendfile_transport_options_count,
  .options_block =	&appendfile_transport_option_defaults,       /* private options defaults */
  .options_len =	sizeof(appendfile_transport_options_block),
  .init =		appendfile_transport_init,
  .code =		appendfile_transport_entry,
  .tidyup =		NULL,
  .closedown =		NULL,
  .local =		TRUE
  },
#endif
#ifdef TRANSPORT_AUTOREPLY
  {
  .driver_name =	US"autoreply",
  .options =		autoreply_transport_options,
  .options_count =	&autoreply_transport_options_count,
  .options_block =	&autoreply_transport_option_defaults,
  .options_len =	sizeof(autoreply_transport_options_block),
  .init =		autoreply_transport_init,
  .code =		autoreply_transport_entry,
  .tidyup =		NULL,
  .closedown =		NULL,
  .local =		TRUE
  },
#endif
#ifdef TRANSPORT_LMTP
  {
  .driver_name =	US"lmtp",
  .options =		lmtp_transport_options,
  .options_count =	&lmtp_transport_options_count,
  .options_block =	&lmtp_transport_option_defaults,
  .options_len =	sizeof(lmtp_transport_options_block),
  .init =		lmtp_transport_init,
  .code =		lmtp_transport_entry,
  .tidyup =		NULL,
  .closedown =		NULL,
  .local =		TRUE
  },
#endif
#ifdef TRANSPORT_PIPE
  {
  .driver_name =	US"pipe",
  .options =		pipe_transport_options,
  .options_count =	&pipe_transport_options_count,
  .options_block =	&pipe_transport_option_defaults,
  .options_len =	sizeof(pipe_transport_options_block),
  .init =		pipe_transport_init,
  .code =		pipe_transport_entry,
  .tidyup =		NULL,
  .closedown =		NULL,
  .local =		TRUE
  },
#endif
#ifdef EXPERIMENTAL_QUEUEFILE
  {
  .driver_name =	US"queuefile",
  .options =		queuefile_transport_options,
  .options_count =	&queuefile_transport_options_count,
  .options_block =	&queuefile_transport_option_defaults,
  .options_len =	sizeof(queuefile_transport_options_block),
  .init =		queuefile_transport_init,
  .code =		queuefile_transport_entry,
  .tidyup =		NULL,
  .closedown =		NULL,
  .local =		TRUE
  },
#endif
#ifdef TRANSPORT_SMTP
  {
  .driver_name =	US"smtp",
  .options =		smtp_transport_options,
  .options_count =	&smtp_transport_options_count,
  .options_block =	&smtp_transport_option_defaults,
  .options_len =	sizeof(smtp_transport_options_block),
  .init =		smtp_transport_init,
  .code =		smtp_transport_entry,
  .tidyup =		NULL,
  .closedown =		smtp_transport_closedown,
  .local =		FALSE
  },
#endif
  { US"" }
};

void
transport_show_supported(FILE * f)
{
fprintf(f, "Transports:");
#ifdef TRANSPORT_APPENDFILE
  fprintf(f, " appendfile");
  #ifdef SUPPORT_MAILDIR
    fprintf(f, "/maildir");	/* damn these subclasses */
  #endif
  #ifdef SUPPORT_MAILSTORE
    fprintf(f, "/mailstore");
  #endif
  #ifdef SUPPORT_MBX
    fprintf(f, "/mbx");
  #endif
#endif
#ifdef TRANSPORT_AUTOREPLY
  fprintf(f, " autoreply");
#endif
#ifdef TRANSPORT_LMTP
  fprintf(f, " lmtp");
#endif
#ifdef TRANSPORT_PIPE
  fprintf(f, " pipe");
#endif
#ifdef EXPERIMENTAL_QUEUEFILE
  fprintf(f, " queuefile");
#endif
#ifdef TRANSPORT_SMTP
  fprintf(f, " smtp");
#endif
fprintf(f, "\n");
}


#ifndef MACRO_PREDEF

struct lookupmodulestr
{
  void *dl;
  struct lookup_module_info *info;
  struct lookupmodulestr *next;
};

static struct lookupmodulestr *lookupmodules = NULL;

static void
addlookupmodule(void *dl, struct lookup_module_info *info)
{
struct lookupmodulestr *p = store_malloc(sizeof(struct lookupmodulestr));

p->dl = dl;
p->info = info;
p->next = lookupmodules;
lookupmodules = p;
lookup_list_count += info->lookupcount;
}

/* only valid after lookup_list and lookup_list_count are assigned */
static void
add_lookup_to_list(lookup_info *info)
{
/* need to add the lookup to lookup_list, sorted */
int pos = 0;

/* strategy is to go through the list until we find
either an empty spot or a name that is higher.
this can't fail because we have enough space. */

while (lookup_list[pos] && (Ustrcmp(lookup_list[pos]->name, info->name) <= 0))
  pos++;

if (lookup_list[pos])
  {
  /* need to insert it, so move all the other items up
  (last slot is still empty, of course) */

  memmove(&lookup_list[pos+1],
	  &lookup_list[pos],
	  sizeof(lookup_info *) * (lookup_list_count-pos-1));
  }
lookup_list[pos] = info;
}


/* These need to be at file level for old versions of gcc (2.95.2 reported),
 * which give parse errors on an extern in function scope.  Each entry needs
 * to also be invoked in init_lookup_list() below  */

#if defined(LOOKUP_CDB) && LOOKUP_CDB!=2
extern lookup_module_info cdb_lookup_module_info;
#endif
#if defined(LOOKUP_DBM) && LOOKUP_DBM!=2
extern lookup_module_info dbmdb_lookup_module_info;
#endif
#if defined(LOOKUP_DNSDB) && LOOKUP_DNSDB!=2
extern lookup_module_info dnsdb_lookup_module_info;
#endif
#if defined(LOOKUP_DSEARCH) && LOOKUP_DSEARCH!=2
extern lookup_module_info dsearch_lookup_module_info;
#endif
#if defined(LOOKUP_IBASE) && LOOKUP_IBASE!=2
extern lookup_module_info ibase_lookup_module_info;
#endif
#if defined(LOOKUP_LDAP)
extern lookup_module_info ldap_lookup_module_info;
#endif
#if defined(LOOKUP_LSEARCH) && LOOKUP_LSEARCH!=2
extern lookup_module_info lsearch_lookup_module_info;
#endif
#if defined(LOOKUP_MYSQL) && LOOKUP_MYSQL!=2
extern lookup_module_info mysql_lookup_module_info;
#endif
#if defined(LOOKUP_NIS) && LOOKUP_NIS!=2
extern lookup_module_info nis_lookup_module_info;
#endif
#if defined(LOOKUP_NISPLUS) && LOOKUP_NISPLUS!=2
extern lookup_module_info nisplus_lookup_module_info;
#endif
#if defined(LOOKUP_ORACLE) && LOOKUP_ORACLE!=2
extern lookup_module_info oracle_lookup_module_info;
#endif
#if defined(LOOKUP_PASSWD) && LOOKUP_PASSWD!=2
extern lookup_module_info passwd_lookup_module_info;
#endif
#if defined(LOOKUP_PGSQL) && LOOKUP_PGSQL!=2
extern lookup_module_info pgsql_lookup_module_info;
#endif
#if defined(LOOKUP_REDIS) && LOOKUP_REDIS!=2
extern lookup_module_info redis_lookup_module_info;
#endif
#if defined(EXPERIMENTAL_LMDB)
extern lookup_module_info lmdb_lookup_module_info;
#endif
#if defined(SUPPORT_SPF)
extern lookup_module_info spf_lookup_module_info;
#endif
#if defined(LOOKUP_SQLITE) && LOOKUP_SQLITE!=2
extern lookup_module_info sqlite_lookup_module_info;
#endif
#if defined(LOOKUP_TESTDB) && LOOKUP_TESTDB!=2
extern lookup_module_info testdb_lookup_module_info;
#endif
#if defined(LOOKUP_WHOSON) && LOOKUP_WHOSON!=2
extern lookup_module_info whoson_lookup_module_info;
#endif


void
init_lookup_list(void)
{
#ifdef LOOKUP_MODULE_DIR
  DIR *dd;
  struct dirent *ent;
  int countmodules = 0;
  int moduleerrors = 0;
#endif
  struct lookupmodulestr *p;
  static BOOL lookup_list_init_done = FALSE;


  if (lookup_list_init_done)
    return;
  lookup_list_init_done = TRUE;

#if defined(LOOKUP_CDB) && LOOKUP_CDB!=2
  addlookupmodule(NULL, &cdb_lookup_module_info);
#endif

#if defined(LOOKUP_DBM) && LOOKUP_DBM!=2
  addlookupmodule(NULL, &dbmdb_lookup_module_info);
#endif

#if defined(LOOKUP_DNSDB) && LOOKUP_DNSDB!=2
  addlookupmodule(NULL, &dnsdb_lookup_module_info);
#endif

#if defined(LOOKUP_DSEARCH) && LOOKUP_DSEARCH!=2
  addlookupmodule(NULL, &dsearch_lookup_module_info);
#endif

#if defined(LOOKUP_IBASE) && LOOKUP_IBASE!=2
  addlookupmodule(NULL, &ibase_lookup_module_info);
#endif

#ifdef LOOKUP_LDAP
  addlookupmodule(NULL, &ldap_lookup_module_info);
#endif

#if defined(LOOKUP_LSEARCH) && LOOKUP_LSEARCH!=2
  addlookupmodule(NULL, &lsearch_lookup_module_info);
#endif

#if defined(LOOKUP_MYSQL) && LOOKUP_MYSQL!=2
  addlookupmodule(NULL, &mysql_lookup_module_info);
#endif

#if defined(LOOKUP_NIS) && LOOKUP_NIS!=2
  addlookupmodule(NULL, &nis_lookup_module_info);
#endif

#if defined(LOOKUP_NISPLUS) && LOOKUP_NISPLUS!=2
  addlookupmodule(NULL, &nisplus_lookup_module_info);
#endif

#if defined(LOOKUP_ORACLE) && LOOKUP_ORACLE!=2
  addlookupmodule(NULL, &oracle_lookup_module_info);
#endif

#if defined(LOOKUP_PASSWD) && LOOKUP_PASSWD!=2
  addlookupmodule(NULL, &passwd_lookup_module_info);
#endif

#if defined(LOOKUP_PGSQL) && LOOKUP_PGSQL!=2
  addlookupmodule(NULL, &pgsql_lookup_module_info);
#endif

#if defined(LOOKUP_REDIS) && LOOKUP_REDIS!=2
  addlookupmodule(NULL, &redis_lookup_module_info);
#endif

#ifdef EXPERIMENTAL_LMDB
  addlookupmodule(NULL, &lmdb_lookup_module_info);
#endif

#ifdef SUPPORT_SPF
  addlookupmodule(NULL, &spf_lookup_module_info);
#endif

#if defined(LOOKUP_SQLITE) && LOOKUP_SQLITE!=2
  addlookupmodule(NULL, &sqlite_lookup_module_info);
#endif

#if defined(LOOKUP_TESTDB) && LOOKUP_TESTDB!=2
  addlookupmodule(NULL, &testdb_lookup_module_info);
#endif

#if defined(LOOKUP_WHOSON) && LOOKUP_WHOSON!=2
  addlookupmodule(NULL, &whoson_lookup_module_info);
#endif

#ifdef LOOKUP_MODULE_DIR
  dd = opendir(LOOKUP_MODULE_DIR);
  if (dd == NULL) {
    DEBUG(D_lookup) debug_printf("Couldn't open %s: not loading lookup modules\n", LOOKUP_MODULE_DIR);
    log_write(0, LOG_MAIN, "Couldn't open %s: not loading lookup modules\n", LOOKUP_MODULE_DIR);
  }
  else {
    const pcre *regex_islookupmod = regex_must_compile(
      US"\\." DYNLIB_FN_EXT "$", FALSE, TRUE);

    DEBUG(D_lookup) debug_printf("Loading lookup modules from %s\n", LOOKUP_MODULE_DIR);
    while ((ent = readdir(dd)) != NULL) {
      char *name = ent->d_name;
      int len = (int)strlen(name);
      if (pcre_exec(regex_islookupmod, NULL, name, len, 0, PCRE_EOPT, NULL, 0) >= 0) {
        int pathnamelen = len + (int)strlen(LOOKUP_MODULE_DIR) + 2;
        void *dl;
        struct lookup_module_info *info;
        const char *errormsg;

        /* SRH: am I being paranoid here or what? */
        if (pathnamelen > big_buffer_size) {
          fprintf(stderr, "Loading lookup modules: %s/%s: name too long\n", LOOKUP_MODULE_DIR, name);
          log_write(0, LOG_MAIN|LOG_PANIC, "%s/%s: name too long\n", LOOKUP_MODULE_DIR, name);
          continue;
        }

        /* SRH: snprintf here? */
        sprintf(CS big_buffer, "%s/%s", LOOKUP_MODULE_DIR, name);

        dl = dlopen(CS big_buffer, RTLD_NOW);// TJ was LAZY
        if (dl == NULL) {
          fprintf(stderr, "Error loading %s: %s\n", name, dlerror());
          moduleerrors++;
          log_write(0, LOG_MAIN|LOG_PANIC, "Error loading lookup module %s: %s\n", name, dlerror());
          continue;
        }

        /* FreeBSD nsdispatch() can trigger dlerror() errors about
         * _nss_cache_cycle_prevention_function; we need to clear the dlerror()
         * state before calling dlsym(), so that any error afterwards only
         * comes from dlsym().
         */
        errormsg = dlerror();

        info = (struct lookup_module_info*) dlsym(dl, "_lookup_module_info");
        if ((errormsg = dlerror()) != NULL) {
          fprintf(stderr, "%s does not appear to be a lookup module (%s)\n", name, errormsg);
          dlclose(dl);
          moduleerrors++;
          log_write(0, LOG_MAIN|LOG_PANIC, "%s does not appear to be a lookup module (%s)\n", name, errormsg);
          continue;
        }
        if (info->magic != LOOKUP_MODULE_INFO_MAGIC) {
          fprintf(stderr, "Lookup module %s is not compatible with this version of Exim\n", name);
          dlclose(dl);
          moduleerrors++;
          log_write(0, LOG_MAIN|LOG_PANIC, "Lookup module %s is not compatible with this version of Exim\n", name);
          continue;
        }

        addlookupmodule(dl, info);
        DEBUG(D_lookup) debug_printf("Loaded \"%s\" (%d lookup types)\n", name, info->lookupcount);
        countmodules++;
      }
    }
    store_free((void*)regex_islookupmod);
    closedir(dd);
  }

  DEBUG(D_lookup) debug_printf("Loaded %d lookup modules\n", countmodules);
#endif

  DEBUG(D_lookup) debug_printf("Total %d lookups\n", lookup_list_count);

  lookup_list = store_malloc(sizeof(lookup_info *) * lookup_list_count);
  memset(lookup_list, 0, sizeof(lookup_info *) * lookup_list_count);

  /* now add all lookups to the real list */
  p = lookupmodules;
  while (p) {
    int j;
    struct lookupmodulestr *pnext;

    for (j = 0; j < p->info->lookupcount; j++)
      add_lookup_to_list(p->info->lookups[j]);

    pnext = p->next;
    store_free(p);
    p = pnext;
  }
  /* just to be sure */
  lookupmodules = NULL;
}

#endif	/*!MACRO_PREDEF*/
/* End of drtables.c */
