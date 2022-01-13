/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


/*************************************************
*       Build configuration header for Exim      *
*************************************************/

/* This auxiliary program builds the file config.h by the following
process:

First, it determines the size of off_t and time_t variables, and generates
macro code to define OFF_T_FMT and TIME_T_FMT as suitable formats, if they are
not already defined in the system-specific header file.

Then it reads Makefile, looking for certain OS-specific definitions which it
uses to define some specific macros. Finally, it reads the defaults file
config.h.defaults.

The defaults file contains normal C #define statements for various macros; if
the name of a macro is found in the environment, the environment value replaces
the default. If the default #define does not contain any value, then that macro
is not copied to the created file unless there is some value in the
environment.

This program is compiled and run as part of the Make process and is not
normally called independently. */


#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>

typedef struct {
  const char *name;
  int *flag;
} have_item;

typedef struct {
  const char *name;
  char *data;
} save_item;

static const char *db_opts[] = { "", "USE_DB", "USE_GDBM", "USE_TDB" };

static int have_ipv6 = 0;
static int have_iconv = 0;

static char errno_quota[256];
static char ostype[256];
static char cc[256];

/* If any entry is an initial substring of another, the longer one must
appear first. */

static have_item have_list[] = {
  { "HAVE_IPV6",      &have_ipv6 },
  { "HAVE_ICONV",     &have_iconv },
  { NULL, NULL}
};

static save_item save_list[] = {
  { "ERRNO_QUOTA",    errno_quota },
  { "OSTYPE",         ostype },
  { "CC",             cc },
  { NULL, NULL}
};


/* Subroutine to check a string for precisely one instance of "%s". If not,
bomb out. */

void
check_percent_ess(char *value, char *name)
{
int OK = 0;
char *p = strstr(value, "%s");
if (p != NULL) OK = strstr(p+2, "%s") == NULL;
if (!OK)
  {
  printf("\n*** \"%s\" (%s) must contain precisely one occurrence of\n"
    "*** \"%%s\". Please review your build-time configuration.\n\n/", value,
    name);
  exit(1);
  }
}


/* Main program */

int
main(int argc, char **argv)
{
off_t test_off_t = 0;
time_t test_time_t = 0;
ino_t test_ino_t;
#if ! (__STDC_VERSION__ >= 199901L)
size_t test_size_t = 0;
ssize_t test_ssize_t = 0;
unsigned long test_ulong_t = 0L;
unsigned int test_uint_t = 0;
#endif
long test_long_t = 0;
int test_int_t = 0;
FILE *base;
FILE *new;
int last_initial = 'A';
int linecount = 0;
int have_auth = 0;
int in_local_makefile = 0;
int use_which_db = 0;
int use_which_db_in_local_makefile = 0;
int support_crypteq = 0;
char buffer[1024];

if (argc != 1)
  {
  printf("*** Buildconfig: called with incorrect arguments\n");
  exit(1);
  }

new = fopen("config.h", "wb");
if (new == NULL)
  {
  printf("*** Buildconfig: failed to open config.h for output\n");
  exit(1);
  }

printf("Building configuration file config.h\n");

fprintf(new, "/*************************************************\n");
fprintf(new, "*           Configuration header for Exim        *\n");
fprintf(new, "*************************************************/\n\n");

fprintf(new, "/* This file was automatically generated from Makefile and "
  "config.h.defaults,\n");
fprintf(new, "using values specified in the configuration file Local/Makefile.\n");
fprintf(new, "Do not edit it. Instead, edit Local/Makefile and "
  "rerun make. */\n\n");

/* First, deal with the printing format for off_t variables. We assume that if
the size of off_t is greater than 4, "%lld" will be available as a format for
printing long long variables, and there will be support for the long long type.
This assumption is known to be OK for the common operating systems. */

fprintf(new, "#ifndef OFF_T_FMT\n");
if (sizeof(test_off_t) > sizeof(test_long_t))
  {
  fprintf(new, "# define OFF_T_FMT  \"%%lld\"\n");
  fprintf(new, "# define LONGLONG_T long long int\n");
  }
else
  {
  fprintf(new, "# define OFF_T_FMT  \"%%ld\"\n");
  fprintf(new, "# define LONGLONG_T long int\n");
  }
fprintf(new, "#endif\n\n");

/* Now do the same thing for time_t variables. If the length is greater than
4, we want to assume long long support (even if off_t was less than 4). If the
length is 4 or less, we can leave LONGLONG_T to whatever was defined above for
off_t. */

fprintf(new, "#ifndef TIME_T_FMT\n");
if (sizeof(test_time_t) > sizeof(test_long_t))
  {
  fprintf(new, "# define TIME_T_FMT  \"%%lld\"\n");
  fprintf(new, "# undef  LONGLONG_T\n");
  fprintf(new, "# define LONGLONG_T long long int\n");
  }
else
  fprintf(new, "# define TIME_T_FMT  \"%%ld\"\n");
fprintf(new, "#endif\n\n");

fprintf(new, "#ifndef INO_T_FMT\n");
if (sizeof(test_ino_t) > sizeof(test_long_t))
  fprintf(new, "# define INO_T_FMT  \"%%llu\"\n");
else
  fprintf(new, "# define INO_T_FMT  \"%%lu\"\n");
fprintf(new, "#endif\n\n");

fprintf(new, "#ifndef PID_T_FMT\n");
fprintf(new, "# define PID_T_FMT  \"%%lu\"\n");
fprintf(new, "#endif\n\n");

/* And for sizeof() results, size_t, which should with C99 be just %zu, deal
with C99 not being ubiquitous yet.  Unfortunately.  Assume ssize_t is same
size as size_t on C99; if someone comes up with a version where it's not, fix
it then. */

#if __STDC_VERSION__ >= 199901L
fprintf(new, "#define SIZE_T_FMT  \"%%zu\"\n");
fprintf(new, "#define SSIZE_T_FMT  \"%%zd\"\n");
#else
if (sizeof(test_size_t) > sizeof (test_ulong_t))
  fprintf(new, "#define SIZE_T_FMT  \"%%llu\"\n");
else if (sizeof(test_size_t) > sizeof (test_uint_t))
  fprintf(new, "#define SIZE_T_FMT  \"%%lu\"\n");
else
  fprintf(new, "#define SIZE_T_FMT  \"%%u\"\n");

if (sizeof(test_ssize_t) > sizeof(test_long_t))
  fprintf(new, "#define SSIZE_T_FMT  \"%%lld\"\n");
else if (sizeof(test_ssize_t) > sizeof(test_int_t))
  fprintf(new, "#define SSIZE_T_FMT  \"%%ld\"\n");
else
  fprintf(new, "#define SSIZE_T_FMT  \"%%d\"\n");
#endif

/* Now search the makefile for certain settings */

base = fopen("Makefile", "rb");
if (base == NULL)
  {
  printf("*** Buildconfig: failed to open Makefile\n");
  (void)fclose(new);
  exit(1);
  }

errno_quota[0] = 0;    /* no over-riding value set */
ostype[0] = 0;         /* just in case */
cc[0] = 0;

while (fgets(buffer, sizeof(buffer), base) != NULL)
  {
  int i;
  have_item *h;
  save_item *s;
  char *p = buffer + (int)strlen(buffer);
  linecount++;
  while (p > buffer && isspace((unsigned char)p[-1])) p--;
  *p = 0;
  p = buffer;
  while (isspace((unsigned char)*p)) p++;

  /* Notice when we hit the user's makefile */

  if (strcmp(p, "# From Local/Makefile") == 0)
    {
    in_local_makefile = 1;
    continue;
    }

  /* Remember the last DB option setting. If we hit two in the user's
  Makefile, complain. */

  for (i = 1; i < sizeof(db_opts)/sizeof(char *); i++)
    {
    int len = (int)strlen(db_opts[i]);
    if (strncmp(p, db_opts[i], len) == 0 && (p[len] == ' ' || p[len] == '='))
      {
      if (in_local_makefile)
        {
        if (use_which_db_in_local_makefile)
          {
          printf("*** Only one of USE_DB, USE_GDBM, or USE_TDB should be "
            "defined in Local/Makefile\n");
          exit(1);
          }
        use_which_db_in_local_makefile = 1;
        }
      use_which_db = i;
      break;
      }
    }
  if (i < sizeof(db_opts)/sizeof(char *)) continue;

  /* Items where we just save a boolean */

  for (h = have_list; h->name != NULL; h++)
    {
    int len = (int)strlen(h->name);
    if (strncmp(p, h->name, len) == 0)
      {
      p += len;
      while (isspace((unsigned char)*p)) p++;
      if (*p++ != '=')
        {
        printf("*** Buildconfig: syntax error in Makefile line %d\n", linecount);
        exit(1);
        }
      while (isspace((unsigned char)*p)) p++;
      if (strcmp(p, "YES") == 0 || strcmp(p, "yes") == 0) *(h->flag) = 1;
        else *(h->flag) = 0;   /* Must reset in case multiple instances */
      break;
      }
    }

  if (h->name != NULL) continue;

  /* Items where we save the complete string */

  for (s = save_list; s->name != NULL; s++)
    {
    int len = (int)strlen(s->name);
    if (strncmp(p, s->name, len) == 0)
      {
      p += len;
      while (isspace((unsigned char)*p)) p++;
      if (*p++ != '=')
        {
        printf("*** Buildconfig: syntax error in Makefile line %d\n", linecount);
        exit(1);
        }
      while (isspace((unsigned char)*p)) p++;
      strcpy(s->data, p);
      }
    }
  }

fprintf(new, "#define HAVE_IPV6             %s\n",
  have_ipv6? "TRUE" : "FALSE");

fprintf(new, "#define HAVE_ICONV            %s\n",
  have_iconv? "TRUE" : "FALSE");

if (errno_quota[0] != 0)
  fprintf(new, "\n#define ERRNO_QUOTA           %s\n", errno_quota);

if (strcmp(cc, "gcc") == 0 &&
    (strstr(ostype, "IRIX") != NULL || strstr(ostype, "AIX") != NULL))
  {
  fprintf(new, "\n/* This switch includes the code to fix the inet_ntoa() */");
  fprintf(new, "\n/* bug when using gcc on an IRIX or AIX system. */");
  fprintf(new, "\n#define USE_INET_NTOA_FIX");
  }

fprintf(new, "\n");
(void)fclose(base);


/* Now handle the macros listed in the defaults */

base = fopen("../src/config.h.defaults", "rb");
if (base == NULL)
  {
  printf("*** Buildconfig: failed to open ../src/config.h.defaults\n");
  (void)fclose(new);
  exit(1);
  }

while (fgets(buffer, sizeof(buffer), base) != NULL)
  {
  int i;
  char name[256];
  char *value;
  char *p = buffer;
  char *q = name;

  while (*p == ' ' || *p == '\t') p++;

  if (strncmp(p, "#ifdef ", 7) == 0
   || strncmp(p, "#ifndef ", 8) == 0
   || strncmp(p, "#if ", 4) == 0
   || strncmp(p, "#endif", 6) == 0
     )
    {
    fputs(buffer, new);
    continue;
    }

  if (strncmp(p, "#define ", 8) != 0) continue;

  p += 8;
  while (*p == ' ' || *p == '\t') p++;

  if (*p < last_initial) fprintf(new, "\n");
  last_initial = *p;

  while (*p && (isalnum((unsigned char)*p) || *p == '_')) *q++ = *p++;
  *q = 0;

  /* USE_DB, USE_GDBM, and USE_TDB are special cases. We want to have only
  one of them set. The scan of the Makefile has saved which was the last one
  encountered. */

  for (i = 1; i < sizeof(db_opts)/sizeof(char *); i++)
    {
    if (strcmp(name, db_opts[i]) == 0)
      {
      if (use_which_db == i)
        fprintf(new, "#define %s %.*syes\n", db_opts[i],
          21 - (int)strlen(db_opts[i]), "                         ");
      else
        fprintf(new, "/* %s not set */\n", name);
      break;
      }
    }
  if (i < sizeof(db_opts)/sizeof(char *)) continue;

  /* EXIM_USER is a special case. We look in the environment for EXIM_USER or
  EXIM_UID (the latter for backward compatibility with Exim 3). If the value is
  not numeric, we look up the user, and default the GID if found. Otherwise,
  EXIM_GROUP or EXIM_GID must be in the environment. */

  if (strcmp(name, "EXIM_UID") == 0)
    {
    uid_t uid = 0;
    gid_t gid = 0;
    int gid_set = 0;
    int uid_not_set = 0;
    char *username = NULL;
    char *groupname = NULL;
    char *s;
    char *user = getenv("EXIM_USER");
    char *group = getenv("EXIM_GROUP");

    if (user == NULL) user = getenv("EXIM_UID");
    if (group == NULL) group = getenv("EXIM_GID");

    if (user == NULL)
      {
      printf("\n*** EXIM_USER has not been defined in any of the Makefiles in "
        "the\n    \"Local\" directory. Please review your build-time "
        "configuration.\n\n");
      return 1;
      }

    while (isspace((unsigned char)(*user))) user++;
    if (*user == 0)
      {
      printf("\n*** EXIM_USER is defined as an empty string in one of the "
        "files\n    in the \"Local\" directory. Please review your build-time"
        "\n    configuration.\n\n");
      return 1;
      }

    for (s = user; *s != 0; s++)
      {
      if (iscntrl((unsigned char)(*s)))
        {
        printf("\n*** EXIM_USER contains the control character 0x%02X in one "
          "of the files\n    in the \"Local\" directory. Please review your "
          "build-time\n    configuration.\n\n", *s);
        return 1;
        }
      }

    /* Numeric uid given */

    if (user[strspn(user, "0123456789")] == 0)
      {
      uid = (uid_t)atoi(user);
      }

    /* User name given. Normally, we look up the uid right away. However,
    people building binary distributions sometimes want to retain the name till
    runtime. This is supported if the name begins "ref:". */

    else if (strncmp(user, "ref:", 4) == 0)
      {
      user += 4;
      while (isspace(*user)) user++;
      username = user;
      gid_set = 1;
      uid_not_set = 1;
      }

    else
      {
      struct passwd *pw = getpwnam(user);
      if (pw == NULL)
        {
        printf("\n*** User \"%s\" (specified in one of the Makefiles) does not "
          "exist.\n    Please review your build-time configuration.\n\n",
          user);
        return 1;
        }

      uid = pw->pw_uid;
      gid = pw->pw_gid;
      gid_set = 1;
      }

    /* Use explicit group if set. */

    if (group != NULL)
      {
      while (isspace((unsigned char)(*group))) group++;
      if (*group == 0)
        {
        printf("\n*** EXIM_GROUP is defined as an empty string in one of "
          "the files in the\n    \"Local\" directory. ");
        if (gid_set)
          {
          printf("If you want the Exim group to be taken from the\n    "
            "password data for the Exim user, just remove the EXIM_GROUP "
            "setting.\n    Otherwise, p");
          }
        else printf("EXIM_USER is defined numerically, so there is no"
          "\n    default for EXIM_GROUP and you must set it explicitly.\n    P");
        printf("lease review your build-time configuration.\n\n");
        return 1;
        }

      for (s = group; *s != 0; s++)
        {
        if (iscntrl((unsigned char)(*s)))
          {
          printf("\n*** EXIM_GROUP contains the control character 0x%02X in one "
            "of the files\n    in the \"Local\" directory. Please review your "
            "build-time\n    configuration.\n\n", *s);
          return 1;
          }
        }

      /* Group name given. This may be by reference or to be looked up now,
      as for user. */

      if (strncmp(group, "ref:", 4) == 0)
        {
        group += 4;
        while (isspace(*group)) group++;
        groupname = group;
        }

      else if (username != NULL)
        {
        groupname = group;
        }

      else if (group[strspn(group, "0123456789")] == 0)
        {
        gid = (gid_t)atoi(group);
        }

      else
        {
        struct group *gr = getgrnam(group);
        if (gr == NULL)
          {
          printf("\n*** Group \"%s\" (specified in one of the Makefiles) does "
            "not exist.\n   Please review your build-time configuration.\n\n",
            group);
          return 1;
          }
        gid = gr->gr_gid;
        }
      }

    /* Else trouble unless found in passwd file with user */

    else if (!gid_set)
      {
      printf("\n*** No group set for Exim. Please review your build-time "
        "configuration.\n\n");
      return 1;
      }

    /* security sanity checks
    if ref: is being used, we can never be sure, but we can take reasonable
    steps to filter out the most obvious ones.  */

    if ((!uid_not_set && uid == 0) ||
        ((username != NULL) && (
          (strcmp(username, "root") == 0) ||
          (strcmp(username, "toor") == 0) )))
      {
      printf("\n*** Exim's internal user must not be root.\n\n");
      return 1;
      }

    /* Output user and group names or uid/gid. When names are set, uid/gid
    are set to zero but will be replaced at runtime. */

    if (username != NULL)
      fprintf(new, "#define EXIM_USERNAME         \"%s\"\n", username);
    if (groupname != NULL)
      fprintf(new, "#define EXIM_GROUPNAME        \"%s\"\n", groupname);

    fprintf(new, "#define EXIM_UID              %d\n", (int)uid);
    fprintf(new, "#define EXIM_GID              %d\n", (int)gid);
    continue;
    }

  /* CONFIGURE_OWNER and CONFIGURE_GROUP are special cases. We look in the
  environment for first. If the value is not numeric, we look up the user or
  group. A lot of this code is similar to that for EXIM_USER, but it's easier
  to keep it separate. */

  if (strcmp(name, "CONFIGURE_OWNER") == 0 ||
      strcmp(name, "CONFIGURE_GROUP") == 0)
    {
    int isgroup = name[10] == 'G';
    uid_t uid = 0;
    gid_t gid = 0;
    const char *s;
    const char *username = NULL;
    const char *user = getenv(name);

    if (user == NULL) user = "";
    while (isspace((unsigned char)(*user))) user++;
    if (*user == 0)
      {
      fprintf(new, "/* %s not set */\n", name);
      continue;
      }

    for (s = user; *s != 0; s++)
      {
      if (iscntrl((unsigned char)(*s)))
        {
        printf("\n*** %s contains the control character 0x%02X in "
          "one of the files\n    in the \"Local\" directory. Please review "
          "your build-time\n    configuration.\n\n", name, *s);
        return 1;
        }
      }

    /* Numeric uid given */

    if (user[strspn(user, "0123456789")] == 0)
      {
      if (isgroup)
        gid = (gid_t)atoi(user);
      else
        uid = (uid_t)atoi(user);
      }

    /* Name given. Normally, we look up the uid or gid right away. However,
    people building binary distributions sometimes want to retain the name till
    runtime. This is supported if the name begins "ref:". */

    else if (strncmp(user, "ref:", 4) == 0)
      {
      user += 4;
      while (isspace(*user)) user++;
      username = user;
      }
else if (isgroup)
      {
      struct group *gr = getgrnam(user);
      if (gr == NULL)
        {
        printf("\n*** Group \"%s\" (specified in one of the Makefiles) does not "
          "exist.\n    Please review your build-time configuration.\n\n",
          user);
        return 1;
        }
      gid = gr->gr_gid;
      }

    else
      {
      struct passwd *pw = getpwnam(user);
      if (pw == NULL)
        {
        printf("\n*** User \"%s\" (specified in one of the Makefiles) does not "
          "exist.\n    Please review your build-time configuration.\n\n",
          user);
        return 1;
        }
      uid = pw->pw_uid;
      }

    /* Output user and group names or uid/gid. When names are set, uid/gid
    are set to zero but will be replaced at runtime. */

    if (username != NULL)
      {
      if (isgroup)
        fprintf(new, "#define CONFIGURE_GROUPNAME         \"%s\"\n", username);
      else
        fprintf(new, "#define CONFIGURE_OWNERNAME         \"%s\"\n", username);
      }

    if (isgroup)
      fprintf(new, "#define CONFIGURE_GROUP              %d\n", (int)gid);
    else
      fprintf(new, "#define CONFIGURE_OWNER              %d\n", (int)uid);
    continue;
    }

  /* FIXED_NEVER_USERS is another special case. Look up the uid values and
  create suitable initialization data for a vector. */

  if (strcmp(name, "FIXED_NEVER_USERS") == 0)
    {
    char *list = getenv("FIXED_NEVER_USERS");
    if (list == NULL)
      {
      fprintf(new, "#define FIXED_NEVER_USERS     0\n");
      }
    else
      {
      int count = 1;
      int i, j;
      uid_t *vector;
      char *p = list;
      while (*p != 0) if (*p++ == ':') count++;

      vector = malloc((count+1) * sizeof(uid_t));
      vector[0] = (uid_t)count;

      for (i = 1, j = 0; i <= count; list++, i++)
        {
        char name[64];

        p = list;
        while (*list != 0 && *list != ':') list++;
        strncpy(name, p, list-p);
        name[list-p] = 0;

        if (name[0] == 0)
          {
          continue;
          }
        else if (name[strspn(name, "0123456789")] == 0)
          {
          vector[j++] = (uid_t)atoi(name);
          }
        else
          {
          struct passwd *pw = getpwnam(name);
          if (pw == NULL)
            {
            printf("\n*** User \"%s\" (specified for FIXED_NEVER_USERS in one of the Makefiles) does not "
              "exist.\n    Please review your build-time configuration.\n\n",
              name);
            return 1;
            }
          vector[j++] = pw->pw_uid;
          }
        }
      fprintf(new, "#define FIXED_NEVER_USERS     %d", j);
      for (i = 0; i < j; i++) fprintf(new, ", %d", (unsigned int)vector[i]);
      fprintf(new, "\n");
      free(vector);
      }
    continue;
    }

  /* WITH_CONTENT_SCAN is another special case: it must be set if it or
  EXPERIMENTAL_DCC is set. */

  if (strcmp(name, "WITH_CONTENT_SCAN") == 0)
    {
    char *wcs = getenv("WITH_CONTENT_SCAN");
    char *dcc = getenv("EXPERIMENTAL_DCC");
    fprintf(new, wcs || dcc
      ? "#define WITH_CONTENT_SCAN     yes\n"
      : "/* WITH_CONTENT_SCAN not set */\n");
    continue;
    }

  /* DISABLE_DKIM is special; must be forced if no SUPPORT_TLS */
  if (strcmp(name, "DISABLE_DKIM") == 0)
    {
    char *d_dkim = getenv("DISABLE_DKIM");
    char *tls = getenv("SUPPORT_TLS");

    if (d_dkim)
      fprintf(new, "#define DISABLE_DKIM          yes\n");
    else if (!tls)
      fprintf(new, "#define DISABLE_DKIM          yes /* forced by lack of TLS */\n");
    else
      fprintf(new, "/* DISABLE_DKIM not set */\n");
    continue;
    }

  /* Otherwise, check whether a value exists in the environment. Remember if
  it is an AUTH setting or SUPPORT_CRYPTEQ. */

  if ((value = getenv(name)) != NULL)
    {
    int len;
    len = 21 - (int)strlen(name);

    if (strncmp(name, "AUTH_", 5) == 0) have_auth = 1;
    if (strncmp(name, "SUPPORT_CRYPTEQ", 15) == 0) support_crypteq = 1;

    /* The text value of LDAP_LIB_TYPE refers to a macro that gets set. */

    if (strcmp(name, "LDAP_LIB_TYPE") == 0)
      {
      if (strcmp(value, "NETSCAPE") == 0 ||
          strcmp(value, "UMICHIGAN") == 0 ||
          strcmp(value, "OPENLDAP1") == 0 ||
          strcmp(value, "OPENLDAP2") == 0 ||
          strcmp(value, "SOLARIS") == 0 ||
          strcmp(value, "SOLARIS7") == 0)              /* Compatibility */
        {
        fprintf(new, "#define LDAP_LIB_%s\n", value);
        }
      else
        {
        printf("\n*** LDAP_LIB_TYPE=%s is not a recognized LDAP library type."
          "\n*** Please review your build-time configuration.\n\n", value);
        return 1;
        }
      }

    else if (strcmp(name, "RADIUS_LIB_TYPE") == 0)
      {
      if (strcmp(value, "RADIUSCLIENT") == 0 ||
          strcmp(value, "RADIUSCLIENTNEW") == 0 ||
          strcmp(value, "RADLIB") == 0)
        {
        fprintf(new, "#define RADIUS_LIB_%s\n", value);
        }
      else
        {
        printf("\n*** RADIUS_LIB_TYPE=%s is not a recognized RADIUS library type."
          "\n*** Please review your build-time configuration.\n\n", value);
        return 1;
        }
      }

    /* Other macros get set to the environment value. */

    else
      {
      fprintf(new, "#define %s ", name);
      while(len-- > 0) fputc(' ', new);

      /* LOG_FILE_PATH is now messy because it can be a path containing %s or
      it can be "syslog" or ":syslog" or "syslog:path" or even "path:syslog". */

      if (strcmp(name, "LOG_FILE_PATH") == 0)
        {
        char *ss = value;
        for(;;)
          {
          char *pp;
          char *sss = strchr(ss, ':');
          if (sss != NULL)
            {
            strncpy(buffer, ss, sss-ss);
            buffer[sss-ss] = 0;  /* For empty case */
            }
          else
	    {
       	    strncpy(buffer, ss, sizeof(buffer));
	    buffer[sizeof(buffer)-1] = 0;
	    }
          pp = buffer + (int)strlen(buffer);
          while (pp > buffer && isspace((unsigned char)pp[-1])) pp--;
          *pp = 0;
          if (buffer[0] != 0 && strcmp(buffer, "syslog") != 0)
            check_percent_ess(buffer, name);
          if (sss == NULL) break;
          ss = sss + 1;
          while (isspace((unsigned char)*ss)) ss++;
          }
        fprintf(new, "\"%s\"\n", value);
        }

      /* Timezone values HEADERS_CHARSET, TCP_WRAPPERS_DAEMON_NAME and
      WHITELIST_D_MACROS get quoted */

      else if (strcmp(name, "TIMEZONE_DEFAULT") == 0||
               strcmp(name, "TCP_WRAPPERS_DAEMON_NAME") == 0||
               strcmp(name, "HEADERS_CHARSET") == 0||
               strcmp(name, "WHITELIST_D_MACROS") == 0)
        fprintf(new, "\"%s\"\n", value);

      /* GnuTLS constants; first is for debugging, others are tuning */

      /* less than 0 is not-active; 0-9 are normal, API suggests higher
      taken without problems */
      else if (strcmp(name, "EXIM_GNUTLS_LIBRARY_LOG_LEVEL") == 0)
        {
        long nv;
        char *end;
        nv = strtol(value, &end, 10);
        if (end != value && *end == '\0' && nv >= -1 && nv <= 100)
          {
          fprintf(new, "%s\n", value);
          }
        else
          {
          printf("Value of %s should be -1..9\n", name);
          return 1;
          }
        }

      /* how many bits Exim, as a client, demands must be in D-H */
      /* 1024 is a historical figure; some sites actually use lower, so we
      permit the value to be lowered "dangerously" low, but not "insanely"
      low.  Though actually, 1024 is becoming "dangerous". */
      else if ((strcmp(name, "EXIM_CLIENT_DH_MIN_MIN_BITS") == 0) ||
               (strcmp(name, "EXIM_CLIENT_DH_DEFAULT_MIN_BITS") == 0) ||
               (strcmp(name, "EXIM_SERVER_DH_BITS_PRE2_12") == 0))
        {
        long nv;
        char *end;
        nv = strtol(value, &end, 10);
        if (end != value && *end == '\0' && nv >= 512 && nv < 500000)
          {
          fprintf(new, "%s\n", value);
          }
        else
          {
          printf("Unreasonable value (%s) of \"%s\".\n", value, name);
          return 1;
          }
        }

      /* For others, quote any paths and don't quote anything else */

      else
        {
        if (value[0] == '/') fprintf(new, "\"%s\"\n", value);
          else fprintf(new, "%s\n", value);
        }
      }
    }

  /* Value not defined in the environment; use the default */

  else
    {
    char *t = p;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '\n') fputs(buffer, new); else
      {
      *t = 0;
      if (strcmp(name, "BIN_DIRECTORY")   == 0 ||
          strcmp(name, "CONFIGURE_FILE")  == 0)
        {
        printf("\n*** %s has not been defined in any of the Makefiles in the\n"
          "    \"Local\" directory. "
          "Please review your build-time configuration.\n\n", name);
        return 1;
        }

      if (strcmp(name, "TIMEZONE_DEFAULT") == 0)
        {
        char *tz = getenv("TZ");
        fprintf(new, "#define TIMEZONE_DEFAULT      ");
        if (tz == NULL) fprintf(new, "NULL\n"); else
          fprintf(new, "\"%s\"\n", tz);
        }

      else fprintf(new, "/* %s not set */\n", name);
      }
    }
  }

(void)fclose(base);

/* If any AUTH macros were defined, ensure that SUPPORT_CRYPTEQ is also
defined. */

if (have_auth)
  {
  if (!support_crypteq) fprintf(new, "/* Force SUPPORT_CRYPTEQ for AUTH */\n"
    "#define SUPPORT_CRYPTEQ\n");
  }

/* Check poll() for timer functionality.
Some OS' have released with it broken. */

  {
  struct timeval before, after;
  int rc;
  size_t us;

  gettimeofday(&before, NULL);
  rc = poll(NULL, 0, 500);
  gettimeofday(&after, NULL);

  us = (after.tv_sec - before.tv_sec) * 1000000 +
    (after.tv_usec - before.tv_usec);

  if (us < 400000)
    fprintf(new, "#define NO_POLL_H\n");
  }

/* End off */

fprintf(new, "\n/* End of config.h */\n");
(void)fclose(new);
return 0;
}

/* End of buildconfig.c */
