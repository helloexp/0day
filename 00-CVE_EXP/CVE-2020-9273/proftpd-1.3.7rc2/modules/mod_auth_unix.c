/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 * Copyright (c) 2001-2017 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Unix authentication module for ProFTPD */

#include "conf.h"

/* AIX has some rather stupid function prototype inconsistencies between
 * their crypt.h and stdlib.h's setkey() declarations.  *sigh*
 */
#if defined(HAVE_CRYPT_H) && !defined(AIX4) && !defined(AIX5)
# include <crypt.h>
#endif

#ifdef PR_USE_SHADOW
# ifdef HAVE_SHADOW_H
#   include <shadow.h>
# endif
#endif

#ifdef HAVE_SYS_SECURITY_H
# include <sys/security.h>
#endif

#ifdef HAVE_KRB_H
# include <krb.h>
#endif

#ifdef HAVE_LOGIN_H
# include <login.h>
#endif

#if defined(HAVE_HPSECURITY_H) || defined(HPUX10) || defined(HPUX11)
# include <hpsecurity.h>
# ifndef COMSEC
#  define COMSEC 1
# endif /* !COMSEC */
#endif /* HAVE_HPSECURITY_H or HPUX10 or HPUX11 */

#if defined(HAVE_PROT_H) || defined(COMSEC)
# include <prot.h>
#endif

#ifdef HAVE_USERSEC_H
# include <usersec.h>
#endif

#ifdef PR_USE_SIA
# ifdef HAVE_SIA_H
#  include <sia.h>
# endif
# ifdef HAVE_SIAD_H
#  include <siad.h>
# endif
#endif /* PR_USE_SIA */

#ifdef CYGWIN
typedef void *HANDLE;
typedef unsigned long DWORD;
# define INVALID_HANDLE_VALUE (HANDLE)(-1)
# define WINAPI __stdcall
DWORD WINAPI GetVersion(void);
extern HANDLE cygwin_logon_user (const struct passwd *, const char *);
extern void cygwin_set_impersonation_token (const HANDLE);
#endif /* CYGWIN */

#ifdef SETGRENT_VOID
# define RETSETGRENTTYPE	void
#else
# define RETSETGRENTTYPE	int
#endif

#include "privs.h"

#ifdef HAVE__PW_STAYOPEN
extern int _pw_stayopen;
#endif

module auth_unix_module;

static const char *pwdfname = "/etc/passwd";
static FILE *pwdf = NULL;

static const char *grpfname = "/etc/group";
static FILE *grpf = NULL;

static int unix_persistent_passwd = FALSE;
static const char *trace_channel = "auth.unix";

#undef PASSWD
#define PASSWD		pwdfname
#undef GROUP
#define	GROUP		grpfname

#ifdef PR_USE_SHADOW

/* Shadow password entries are stored as number of days, not seconds
 * and are -1 if unused
 */
#define SP_CVT_DAYS(x)	((x) == (time_t)-1 ? (x) : ((x) * 86400))

#endif /* PR_USE_SHADOW */

/* mod_auth_unix option flags */
#define AUTH_UNIX_OPT_AIX_NO_RLOGIN		0x0001
#define AUTH_UNIX_OPT_NO_GETGROUPLIST		0x0002
#define AUTH_UNIX_OPT_MAGIC_TOKEN_CHROOT	0x0004
#define AUTH_UNIX_OPT_NO_INITGROUPS		0x0008
#define AUTH_UNIX_OPT_AIX_NO_AUTHENTICATE	0x0010

static unsigned long auth_unix_opts = 0UL;

/* Necessary prototypes */
static void auth_unix_exit_ev(const void *, void *);
static int auth_unix_sess_init(void);

static void p_setpwent(void) {
  if (pwdf != NULL) {
    rewind(pwdf);

  } else {
    pwdf = fopen(PASSWD, "r");
    if (pwdf == NULL) {
      pr_log_pri(PR_LOG_ERR, "unable to open password file %s for reading: %s",
        PASSWD, strerror(errno));
    }
  }
}

static void p_endpwent(void) {
  if (pwdf != NULL) {
    fclose(pwdf);
    pwdf = NULL;
  }
}

static RETSETGRENTTYPE p_setgrent(void) {
  if (grpf != NULL) {
    rewind(grpf);

  } else {
    grpf = fopen(GROUP, "r");
    if (grpf == NULL) {
      pr_log_pri(PR_LOG_ERR, "unable to open group file %s for reading: %s",
        GROUP, strerror(errno));
    }
  }

#ifndef SETGRENT_VOID
  return 0;
#endif
}

static void p_endgrent(void) {
  if (grpf != NULL) {
    fclose(grpf);
    grpf = NULL;
  }
}

static struct passwd *p_getpwent(void) {
  if (pwdf == NULL) {
    p_setpwent();
  }

  if (pwdf == NULL) {
    return NULL;
  }

  return fgetpwent(pwdf);
}

static struct group *p_getgrent(void) {
  if (grpf == NULL) {
    p_setgrent();
  }

  if (grpf == NULL) {
    return NULL;
  }

  return fgetgrent(grpf);
}

static struct passwd *p_getpwnam(const char *name) {
  struct passwd *pw = NULL;
  size_t name_len;

  p_setpwent();
  name_len = strlen(name);

  while ((pw = p_getpwent()) != NULL) {
    pr_signals_handle();

    if (strncmp(name, pw->pw_name, name_len + 1) == 0) {
      break;
    }
  }

  return pw;
}

static struct passwd *p_getpwuid(uid_t uid) {
  struct passwd *pw = NULL;

  p_setpwent();
  while ((pw = p_getpwent()) != NULL) {
    pr_signals_handle();

    if (pw->pw_uid == uid) {
      break;
    }
  }

  return pw;
}

static struct group *p_getgrnam(const char *name) {
  struct group *gr = NULL;
  size_t name_len;

  p_setgrent();
  name_len = strlen(name);

  while ((gr = p_getgrent()) != NULL) {
    pr_signals_handle();

    if (strncmp(name, gr->gr_name, name_len + 1) == 0) {
      break;
    }
  }

  return gr;
}

static struct group *p_getgrgid(gid_t gid) {
  struct group *gr = NULL;

  p_setgrent();
  while ((gr = p_getgrent()) != NULL) {
    pr_signals_handle();

    if (gr->gr_gid == gid) {
      break;
    }
  }

  return gr;
}

MODRET pw_setpwent(cmd_rec *cmd) {
  if (unix_persistent_passwd) {
    p_setpwent();

  } else {
    setpwent();
  }

  return PR_DECLINED(cmd);
}

MODRET pw_endpwent(cmd_rec *cmd) {
  if (unix_persistent_passwd) {
    p_endpwent();

  } else {
    endpwent();
  }

  return PR_DECLINED(cmd);
}

MODRET pw_setgrent(cmd_rec *cmd) {
  if (unix_persistent_passwd) {
    p_setgrent();

  } else {
    setgrent();
  }

  return PR_DECLINED(cmd);
}

MODRET pw_endgrent(cmd_rec *cmd) {
  if (unix_persistent_passwd) {
    p_endgrent();

  } else {
    endgrent();
  }

  return PR_DECLINED(cmd);
}

MODRET pw_getgrent(cmd_rec *cmd) {
  struct group *gr = NULL;

  if (unix_persistent_passwd) {
    gr = p_getgrent();

  } else {
    gr = getgrent();
  }

  return gr ? mod_create_data(cmd, gr) : PR_DECLINED(cmd);
}

MODRET pw_getpwent(cmd_rec *cmd) {
  struct passwd *pw = NULL;

  if (unix_persistent_passwd) {
    pw = p_getpwent();

  } else {
    pw = getpwent();
  }

  return pw ? mod_create_data(cmd, pw) : PR_DECLINED(cmd);
}

MODRET pw_getpwuid(cmd_rec *cmd) {
  struct passwd *pw = NULL;
  uid_t uid;

  uid = *((uid_t *) cmd->argv[0]);
  if (unix_persistent_passwd) {
    pw = p_getpwuid(uid);

  } else {
    pw = getpwuid(uid);
  }

  return pw ? mod_create_data(cmd, pw) : PR_DECLINED(cmd);
}

MODRET pw_getpwnam(cmd_rec *cmd) {
  struct passwd *pw = NULL;
  const char *name;

  name = cmd->argv[0];
  if (unix_persistent_passwd) {
    pw = p_getpwnam(name);

  } else {
    pw = getpwnam(name);
  }

  if (pw == NULL) {
    return PR_DECLINED(cmd);
  }

  if (auth_unix_opts & AUTH_UNIX_OPT_MAGIC_TOKEN_CHROOT) {
    char *home_dir, *ptr;

    /* Here is where we do the "magic token" chroot monstrosity inflicted
     * on the world by wu-ftpd.
     *
     * If the magic token '/./' appears in the user's home directory, the
     * directory portion before the token is the directory to use for
     * the chroot; the directory portion after the token is the directory
     * to use for the initial chdir.
     */

    home_dir = pstrdup(cmd->tmp_pool, pw->pw_dir);

    /* We iterate through the home directory string since it is possible
     * for the '.' character to appear without it being part of the magic
     * token.
     */
    ptr = strchr(home_dir, '.');
    while (ptr != NULL) {
      pr_signals_handle();

      /* If we're at the start of the home directory string, stop looking:
       * this home directory is not really valid anyway.
       */
      if (ptr == home_dir) {
        break;
      }

      /* Back up one character. */
      ptr--;

      /* If we're at the start of the home directory now, stop looking:
       * this home directory cannot contain a valid magic token.  I.e.
       *
       * /./home/foo
       *
       * cannot be valid, as there is no directory portion before the
       * token.
       */
      if (ptr == home_dir) {
        break;
      }

      if (strncmp(ptr, "/./", 3) == 0) {
        char *default_chdir;
        config_rec *c;

        *ptr = '\0';
        default_chdir = pstrdup(cmd->tmp_pool, ptr + 2);

        /* In order to make sure that this user is chrooted to this
         * directory, we remove all DefaultRoot directives and add a new
         * one.  Same for the DefaultChdir directive.
         */

        (void) remove_config(main_server->conf, "DefaultRoot", FALSE);
        c = add_config_param_set(&main_server->conf, "DefaultRoot", 1, NULL);
        c->argv[0] = pstrdup(c->pool, home_dir);

        (void) remove_config(main_server->conf, "DefaultChdir", FALSE);
        c = add_config_param_set(&main_server->conf, "DefaultChdir", 1, NULL);
        c->argv[0] = pstrdup(c->pool, default_chdir);

        pr_log_debug(DEBUG9, "AuthUnixOption magicTokenChroot: "
          "found magic token in '%s', using 'DefaultRoot %s' and "
          "'DefaultChdir %s'", pw->pw_dir, home_dir, default_chdir);

        /* We need to use a long-lived memory pool for overwriting the
         * normal home directory.
         */
        pw->pw_dir = pstrdup(session.pool, home_dir);

        break;
      }

      ptr = strchr(ptr + 2, '.');
    }
  }

  return pw ? mod_create_data(cmd, pw) : PR_DECLINED(cmd);
}

MODRET pw_getgrnam(cmd_rec *cmd) {
  struct group *gr = NULL;
  const char *name;

  name = cmd->argv[0];
  if (unix_persistent_passwd) {
    gr = p_getgrnam(name);

  } else {
    gr = getgrnam(name);
  }

  return gr ? mod_create_data(cmd, gr) : PR_DECLINED(cmd);
}

MODRET pw_getgrgid(cmd_rec *cmd) {
  struct group *gr = NULL;
  gid_t gid;

  gid = *((gid_t *) cmd->argv[0]);
  if (unix_persistent_passwd) {
    gr = p_getgrgid(gid);

  } else {
    gr = getgrgid(gid);
  }

  return gr ? mod_create_data(cmd, gr) : PR_DECLINED(cmd);
}

#ifdef PR_USE_SHADOW
static char *get_pwd_info(pool *p, const char *u, time_t *lstchg, time_t *min,
    time_t *max, time_t *warn, time_t *inact, time_t *expire) {
  struct spwd *sp;
  char *cpw = NULL;

  pr_trace_msg(trace_channel, 7,
    "looking up user '%s' via Unix shadow mechanism", u);

  PRIVS_ROOT
#ifdef HAVE_SETSPENT
  setspent();
#endif /* HAVE_SETSPENT */

  sp = getspnam(u);
  if (sp != NULL) {
    cpw = pstrdup(p, sp->sp_pwdp);

    if (lstchg != NULL) {
      *lstchg = SP_CVT_DAYS(sp->sp_lstchg);
    }

    if (min != NULL) {
      *min = SP_CVT_DAYS(sp->sp_min);
    }

    if (max != NULL) {
      *max = SP_CVT_DAYS(sp->sp_max);
    }

#ifdef HAVE_SPWD_SP_WARN
    if (warn != NULL) {
      *warn = SP_CVT_DAYS(sp->sp_warn);
    }
#endif /* HAVE_SPWD_SP_WARN */

#ifdef HAVE_SPWD_SP_INACT
    if (inact != NULL) {
      *inact = SP_CVT_DAYS(sp->sp_inact);
    }
#endif /* HAVE_SPWD_SP_INACT */

#ifdef HAVE_SPWD_SP_EXPIRE
    if (expire != NULL) {
      *expire = SP_CVT_DAYS(sp->sp_expire);
    }
#endif /* HAVE_SPWD_SP_EXPIRE */

  } else {
    pr_log_debug(DEBUG5, "mod_auth_unix: getspnam(3) for user '%s' error: %s",
      u, strerror(errno));
  }

#ifdef PR_USE_AUTO_SHADOW
  if (sp == NULL) {
    struct passwd *pw;

    pr_trace_msg(trace_channel, 7,
      "looking up user '%s' via Unix autoshadow mechanism", u);

    endspent();
    PRIVS_RELINQUISH

    pw = getpwnam(u);
    if (pw != NULL) {
      cpw = pstrdup(p, pw->pw_passwd);

      if (lstchg != NULL) {
        *lstchg = (time_t) -1;
      }

      if (min != NULL) {
        *min = (time_t) -1;
      }

      if (max != NULL) {
        *max = (time_t) -1;
      }

      if (warn != NULL) {
        *warn = (time_t) -1;
      }

      if (inact != NULL) {
        *inact = (time_t) -1;
      }

      if (expire != NULL) {
        *expire = (time_t) -1;
      }

    } else {
      pr_log_debug(DEBUG5, "mod_auth_unix: getpwnam(3) for user '%s' error: %s",
        u, strerror(errno));
    }

  } else {
    PRIVS_RELINQUISH
  }
#else
  endspent();
  PRIVS_RELINQUISH
#endif /* PR_USE_AUTO_SHADOW */

  return cpw;
}

#else /* PR_USE_SHADOW */

static char *get_pwd_info(pool *p, const char *u, time_t *lstchg, time_t *min,
    time_t *max, time_t *warn, time_t *inact, time_t *expire) {
  char *cpw = NULL;
#if defined(HAVE_GETPRPWENT) || defined(COMSEC)
  struct pr_passwd *prpw;
#endif
#if !defined(HAVE_GETPRPWENT) || defined(COMSEC)
  struct passwd *pw;
#endif

 /* Some platforms (i.e. BSD) provide "transparent" shadowing, which
  * requires that we are root in order to have the password member
  * filled in.
  */

  pr_trace_msg(trace_channel, 7,
    "looking up user '%s' via normal Unix mechanism", u);

  PRIVS_ROOT
#if !defined(HAVE_GETPRPWENT) || defined(COMSEC)
# ifdef COMSEC
  if (!iscomsec()) {
# endif /* COMSEC */
  endpwent();
#if defined(BSDI3) || defined(BSDI4)
  /* endpwent() seems to be buggy on BSDI3.1 (is this true for 4.0?)
   * setpassent(0) _seems_ to do the same thing, however this conflicts
   * with the man page documented behavior.  Argh, why do all the bsds
   * have to be different in this area (except OpenBSD, grin).
   */
  setpassent(0);
#else /* BSDI3 || BSDI4 */
  setpwent();
#endif /* BSDI3 || BSDI4 */

  pw = getpwnam(u);
  if (pw) {
    cpw = pstrdup(p, pw->pw_passwd);

    if (lstchg)
      *lstchg = (time_t) -1;

    if (min)
      *min = (time_t) -1;

    if (max)
      *max = (time_t) -1;

    if (warn)
      *warn = (time_t) -1;

    if (inact)
      *inact = (time_t) -1;

    if (expire)
      *expire = (time_t) -1;

  } else {
    pr_log_debug(DEBUG5, "mod_auth_unix: getpwnam(3) for user '%s' error: %s",
      u, strerror(errno));
  }

  endpwent();
#ifdef COMSEC
  } else {
#endif /* COMSEC */
#endif /* !HAVE_GETPRWENT or COMSEC */

#if defined(HAVE_GETPRPWENT) || defined(COMSEC)
  endprpwent();
  setprpwent();

  prpw = getprpwnam((char *) u);

  if (prpw) {
    cpw = pstrdup(p, prpw->ufld.fd_encrypt);

    if (lstchg)
      *lstchg = (time_t) -1;

    if (min)
      *min = prpw->ufld.fd_min;

    if (max)
      *max = (time_t) -1;

    if (warn)
      *warn = (time_t) -1;

    if (inact)
      *inact = (time_t) -1;

    if (expire)
      *expire = prpw->ufld.fd_expire;
  }

  endprpwent();
#ifdef COMSEC
  }
#endif /* COMSEC */
#endif /* HAVE_GETPRPWENT or COMSEC */

  PRIVS_RELINQUISH
#if defined(BSDI3) || defined(BSDI4)
  setpassent(1);
#endif
  return cpw;
}

#endif /* PR_USE_SHADOW */

/* High-level auth handlers
 */

/* cmd->argv[0] : user name
 * cmd->argv[1] : cleartext password
 */

MODRET pw_auth(cmd_rec *cmd) {
  int res;
  time_t now;
  char *cleartxt_passwd;
  time_t lstchg = -1, max = -1, inact = -1, expire = -1;
  const char *name;
  size_t cleartxt_passwdlen;

  name = cmd->argv[0];

  cleartxt_passwd = get_pwd_info(cmd->tmp_pool, name, &lstchg, NULL, &max,
    NULL, &inact, &expire);
  if (cleartxt_passwd == NULL) {
    return PR_DECLINED(cmd);
  }

  res = pr_auth_check(cmd->tmp_pool, cleartxt_passwd, cmd->argv[0],
    cmd->argv[1]);
  cleartxt_passwdlen = strlen(cleartxt_passwd);
  pr_memscrub(cleartxt_passwd, cleartxt_passwdlen);

  if (res < PR_AUTH_OK) {
    return PR_ERROR_INT(cmd, res);
  }

  time(&now);

  if (lstchg > (time_t) 0 &&
      max > (time_t) 0 &&
      inact > (time_t) 0) {
    if (now > (lstchg + max + inact)) {
      return PR_ERROR_INT(cmd, PR_AUTH_AGEPWD);
    }
  }

  if (expire > (time_t) 0 &&
      now > expire) {
    return PR_ERROR_INT(cmd, PR_AUTH_DISABLEDPWD);
  }

  session.auth_mech = "mod_auth_unix.c";
  return PR_HANDLED(cmd);
}

MODRET pw_authz(cmd_rec *cmd) {
  time_t now;
  char *user, *cleartxt_passwd;
  time_t lstchg = -1, max = -1, inact = -1, expire = -1;
  size_t cleartxt_passwdlen;

  user = cmd->argv[0];

  cleartxt_passwd = get_pwd_info(cmd->tmp_pool, user, &lstchg, NULL, &max,
    NULL, &inact, &expire);
  if (cleartxt_passwd == NULL) {
    pr_log_auth(LOG_WARNING, "no password information found for user '%.100s'",
      user);
    return PR_ERROR_INT(cmd, PR_AUTH_NOPWD);
  }

  cleartxt_passwdlen = strlen(cleartxt_passwd);
  pr_memscrub(cleartxt_passwd, cleartxt_passwdlen);

  time(&now);

  if (lstchg > (time_t) 0 &&
      max > (time_t) 0 &&
      inact > (time_t) 0) {
    if (now > (lstchg + max + inact)) {
      pr_log_auth(LOG_WARNING,
        "account for user '%.100s' disabled due to inactivity", user);
      return PR_ERROR_INT(cmd, PR_AUTH_AGEPWD);
    }
  }

  if (expire > (time_t) 0 &&
      now > expire) {
    pr_log_auth(LOG_WARNING,
      "account for user '%.100s' disabled due to password expiration", user);
    return PR_ERROR_INT(cmd, PR_AUTH_DISABLEDPWD);
  }

  /* XXX Any other implementations here? */

#ifdef HAVE_LOGINRESTRICTIONS
  if (!(auth_unix_opts & AUTH_UNIX_OPT_AIX_NO_RLOGIN)) {
    int res, xerrno, code = 0;
    char *reason = NULL;

    /* Check for account login restrictions and such using AIX-specific
     * functions.
     */
    PRIVS_ROOT
    res = loginrestrictions(user, S_RLOGIN, NULL, &reason);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res != 0) {
      if (reason != NULL &&
          *reason) {
        pr_trace_msg(trace_channel, 9,
          "AIX loginrestrictions() failed for user '%s': %.100s", user, reason);
        pr_log_auth(LOG_WARNING, "login restricted for user '%s': %.100s",
          user, reason);
      }

      pr_log_auth(LOG_NOTICE,
        "AIX loginrestrictions() failed for user '%s': %s", user,
        strerror(xerrno));

      return PR_ERROR_INT(cmd, PR_AUTH_DISABLEDPWD);
    }

    PRIVS_ROOT
    code = passwdexpired(user, &reason);
    PRIVS_RELINQUISH

    switch (code) {
      case 0:
        /* Password not expired for user */
        break;

      case 1:
        /* Password expired and needs to be changed */
        pr_log_auth(LOG_WARNING, "password expired for user '%s': %.100s",
          cmd->argv[0], reason);
        return PR_ERROR_INT(cmd, PR_AUTH_AGEPWD);

      case 2:
        /* Password expired, requires sysadmin to change it */
        pr_log_auth(LOG_WARNING,
          "password expired for user '%s', requires sysadmin intervention: "
          "%.100s", user, reason);
        return PR_ERROR_INT(cmd, PR_AUTH_AGEPWD);

      default:
        /* Other error */
        pr_log_auth(LOG_WARNING, "AIX passwdexpired() failed for user '%s': "
          "%.100s", user, reason);
        return PR_ERROR_INT(cmd, PR_AUTH_DISABLEDPWD);
    }
  }
#endif /* !HAVE_LOGINRESTRICTIONS */

  return PR_HANDLED(cmd);
}

/* cmd->argv[0] = hashed password
 * cmd->argv[1] = user
 * cmd->argv[2] = cleartext
 */

MODRET pw_check(cmd_rec *cmd) {
  const char *cpw = cmd->argv[0];
  const char *pw = cmd->argv[2];
  modret_t *mr = NULL;
  cmd_rec *cmd2 = NULL;
  char *crypted_text = NULL;

#ifdef PR_USE_SIA
  SIAENTITY *ent = NULL;
  int res = SIASUCCESS;
  char *info[2];
  struct passwd *pwd;
  char *user = NULL;
#endif

#ifdef COMSEC
  if (iscomsec()) {
    if (strcmp(bigcrypt((char *) pw, (char *) cpw), cpw) != 0) {
      return PR_DECLINED(cmd);
    }

  } else {
#endif /* COMSEC */

#ifdef PR_USE_SIA
  /* Use Tru64's C2 SIA subsystem for authenticating this user. */
  user = cmd->argv[1];

  pr_log_auth(PR_LOG_INFO, "using SIA for user '%s'", user);

  info[0] = "ProFTPD";
  info[1] = NULL;

  /* Prepare the SIA subsystem. */
  PRIVS_ROOT
  res = sia_ses_init(&ent, 1, info, NULL, user, NULL, 0, NULL);
  if (res != SIASUCCESS) {
    pr_log_auth(PR_LOG_NOTICE, "sia_ses_init() returned %d for user '%s'", res,
      user);

  } else {

    res = sia_ses_authent(NULL, pw, ent);
    if (res != SIASUCCESS) {
      sia_ses_release(&ent);
      PRIVS_RELINQUISH
      pr_log_auth(PR_LOG_NOTICE, "sia_ses_authent() returned %d for user '%s'",
        res, user);
      return PR_ERROR(cmd);
    }

    res = sia_ses_estab(NULL, ent);
    if (res != SIASUCCESS) {
      PRIVS_RELINQUISH
      pr_log_auth(PR_LOG_NOTICE, "sia_ses_estab() returned %d for user '%s'",
        res, user);
      return PR_ERROR(cmd);
    }

    res = sia_ses_release(&ent);
    if (res != SIASUCCESS) {
      PRIVS_RELINQUISH
      pr_log_auth(PR_LOG_NOTICE, "sia_ses_release() returned %d", res);
      return PR_ERROR(cmd);
    }
  }
  PRIVS_RELINQUISH

  if (res != SIASUCCESS) {
    return PR_DECLINED(cmd);
  }

#else /* !PR_USE_SIA */

# ifdef CYGWIN
  /* We have to do special Windows NT voodoo with Cygwin in order to be
   * able to switch UID/GID. More info at
   * http://cygwin.com/cygwin-ug-net/ntsec.html#NTSEC-SETUID
   */
  if (GetVersion() < 0x80000000) {
    struct passwd *pwent = NULL;
    HANDLE token;

    /* A struct passwd * is needed.  To look one up via pw_getpwnam(), though,
     * we'll need a cmd_rec.
     */
    cmd2 = pr_cmd_alloc(cmd->tmp_pool, 1, cmd->argv[1]);

    /* pw_getpwnam() returns a MODRET, so we need to handle that.  Yes, this
     * might have been easier if we'd used pr_auth_getpwnam(), but that would
     * dispatch through other auth modules, which is _not_ what we want.
     */
    mr = pw_getpwnam(cmd2);

    /* Note: we don't handle the case where pw_getpwnam() returns anything
     * other than HANDLED at the moment.
     */

    if (MODRET_ISHANDLED(mr) &&
        MODRET_HASDATA(mr)) {
      pwent = mr->data;

      token = cygwin_logon_user((const struct passwd *) pwent, pw);
      if (token == INVALID_HANDLE_VALUE) {
        pr_log_pri(PR_LOG_NOTICE, "error authenticating Cygwin user: %s",
          strerror(errno));
        return PR_DECLINED(cmd);
      }

      cygwin_set_impersonation_token(token);

    } else {
      return PR_DECLINED(cmd);
    }

  } else {
# endif /* CYGWIN */

#ifdef HAVE_AUTHENTICATE
  if (!(auth_unix_opts & AUTH_UNIX_OPT_AIX_NO_AUTHENTICATE)) {
    int res, xerrno, reenter = 0;
    char *user, *passwd, *msg = NULL;

    user = cmd->argv[1];
    passwd = cmd->argv[2];

    pr_trace_msg(trace_channel, 9, "calling AIX authenticate() for user '%s'",
      user);

    PRIVS_ROOT
    do {
      res = authenticate(user, passwd, &reenter, &msg);
      xerrno = errno;

      pr_trace_msg(trace_channel, 9,
        "AIX authenticate result: %d (msg '%.100s')", res, msg);

    } while (reenter != 0);
    PRIVS_RELINQUISH

    /* AIX indicates failure with a return value of 1. */
    if (res != 0) {
      pr_log_auth(LOG_WARNING,
       "AIX authenticate failed for user '%s': %.100s", user, msg);

      if (xerrno == ENOENT) {
        return PR_ERROR_INT(cmd, PR_AUTH_NOPWD);
      }

      return PR_ERROR_INT(cmd, PR_AUTH_DISABLEDPWD);
    }
  }
#endif /* HAVE_AUTHENTICATE */

  /* Call pw_authz here, to make sure the user is authorized to login. */

  if (cmd2 == NULL) {
    cmd2 = pr_cmd_alloc(cmd->tmp_pool, 1, cmd->argv[1]);
  }

  mr = pw_authz(cmd2);
  if (MODRET_ISERROR(mr)) {
    int err_code;

    err_code = MODRET_ERROR(mr);
    return PR_ERROR_INT(cmd, err_code);
  }

  if (MODRET_ISDECLINED(mr)) {
    return PR_DECLINED(cmd);
  }

  crypted_text = (char *) crypt(pw, cpw);
  if (crypted_text == NULL) {
    pr_log_pri(PR_LOG_NOTICE, "crypt(3) failed: %s", strerror(errno));
    return PR_DECLINED(cmd);
  }

  if (strcmp(crypted_text, cpw) != 0) {
    return PR_DECLINED(cmd);
  }

# ifdef CYGWIN
  }
# endif /* CYGWIN */

#endif /* PR_USE_SIA */

#ifdef COMSEC
  }
#endif /* COMSEC */

  session.auth_mech = "mod_auth_unix.c";
  return PR_HANDLED(cmd);
}

MODRET pw_uid2name(cmd_rec *cmd) {
  struct passwd *pw = NULL;
  uid_t uid;

  uid = *((uid_t *) cmd->argv[0]);

  if (unix_persistent_passwd) {
    pw = p_getpwuid(uid);

  } else {
    pw = getpwuid(uid);
  }

  if (pw) {
    return mod_create_data(cmd, pw->pw_name);
  }

  return PR_DECLINED(cmd);
}

MODRET pw_gid2name(cmd_rec *cmd) {
  struct group *gr = NULL;
  gid_t gid;

  gid = *((gid_t *) cmd->argv[0]);
  if (unix_persistent_passwd) {
    gr = p_getgrgid(gid);

  } else {
    gr = getgrgid(gid);
  }

  if (gr) {
    return mod_create_data(cmd, gr->gr_name);
  }

  return PR_DECLINED(cmd);
}

MODRET pw_name2uid(cmd_rec *cmd) {
  struct passwd *pw = NULL;
  const char *name;

  name = cmd->argv[0];

  if (unix_persistent_passwd) {
    pw = p_getpwnam(name);

  } else {
    pw = getpwnam(name);
  }

  return pw ? mod_create_data(cmd, (void *) &pw->pw_uid) : PR_DECLINED(cmd);
}

MODRET pw_name2gid(cmd_rec *cmd) {
  struct group *gr = NULL;
  const char *name;

  name = cmd->argv[0];

  if (unix_persistent_passwd) {
    gr = p_getgrnam(name);

  } else {
    gr = getgrnam(name);
  }

  return gr ? mod_create_data(cmd, (void *) &gr->gr_gid) : PR_DECLINED(cmd);
}

static int get_groups_by_getgrset(const char *user, gid_t primary_gid,
    array_header *gids, array_header *groups,
    struct group *(*my_getgrgid)(gid_t)) {
  int res;
#ifdef HAVE_GETGRSET
  gid_t group_ids[NGROUPS_MAX];
  unsigned int ngroups = 0;
  register unsigned int i;
  char *grgid, *grouplist, *ptr;

  pr_trace_msg("auth", 4,
    "using getgrset(3) to look up group membership");

  grouplist = getgrset(user);
  if (grouplist == NULL) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "getgrset(3) error: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  ptr = grouplist;
  memset(group_ids, 0, sizeof(group_ids));

  /* The getgrset(3) function returns a string which is a comma-delimited
   * list of group IDs.
   */
  grgid = strsep(&grouplist, ",");
  while (grgid != NULL) {
    gid_t gid;

    pr_signals_handle();

    if (ngroups >= sizeof(group_ids)) {
      /* Reached capacity of the group_ids array. */
      break;
    }

    pr_str2gid(grgid, &gid);

    /* Skip the primary group. */
    if (gid == primary_gid) {
      grgid = strsep(&grouplist, ",");
      continue;
    }

    group_ids[ngroups] = gid;
    ngroups++;

    grgid = strsep(&grouplist, ",");
  }

  for (i = 0; i < ngroups; i++) {
    struct group *gr;

    gr = my_getgrgid(group_ids[i]);
    if (gr != NULL) {
      if (gids != NULL &&
          primary_gid != gr->gr_gid) {
        *((gid_t *) push_array(gids)) = gr->gr_gid;
      }

      if (groups != NULL &&
          primary_gid != gr->gr_gid) {
        *((char **) push_array(groups)) = pstrdup(session.pool,
          gr->gr_name);
      }
    }
  }

  free(ptr);
  res = 0;

#else
  errno = ENOSYS;
  res = -1;
#endif /* HAVE_GETGRSET */

  return res;
}

static int get_groups_by_getgrouplist(const char *user, gid_t primary_gid,
    array_header *gids, array_header *groups,
    struct group *(*my_getgrgid)(gid_t)) {
  int res;
#ifdef HAVE_GETGROUPLIST
  int use_getgrouplist = TRUE;
  gid_t group_ids[NGROUPS_MAX];
  int ngroups = NGROUPS_MAX;
  register int i;

  /* Determine whether to use getgrouplist(3), if available.  Older glibc
   * versions (i.e. 2.2.4 and older) had buggy getgrouplist() implementations
   * which allowed for buffer overflows (see CVS-2003-0689); do not use
   * getgrouplist() on such glibc versions.
   */

# if defined(__GLIBC__) && \
     defined(__GLIBC_MINOR__) && \
     __GLIBC__ <= 2 && \
     __GLIBC_MINOR__ < 3
  use_getgrouplist = FALSE;
# endif

  /* Use of getgrouplist(3) might have been disabled via the "NoGetgrouplist"
   * AuthUnixOption as well.
   */
  if (auth_unix_opts & AUTH_UNIX_OPT_NO_GETGROUPLIST) {
    use_getgrouplist = FALSE;
  }

  if (use_getgrouplist == FALSE) {
    errno = ENOSYS;
    return -1;
  }

  pr_trace_msg("auth", 4,
    "using getgrouplist(3) to look up group membership");

  memset(group_ids, 0, sizeof(group_ids));
#ifdef HAVE_GETGROUPLIST_TAKES_INTS
  res = getgrouplist(user, primary_gid, (int *) group_ids, &ngroups);
#else
  res = getgrouplist(user, primary_gid, group_ids, &ngroups);
#endif
  if (res < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "getgrouplist(3) error: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  for (i = 0; i < ngroups; i++) {
    struct group *gr;

    gr = my_getgrgid(group_ids[i]);
    if (gr != NULL) {
      if (gids != NULL &&
          primary_gid != gr->gr_gid) {
        *((gid_t *) push_array(gids)) = gr->gr_gid;
      }

      if (groups != NULL &&
          primary_gid != gr->gr_gid) {
        *((char **) push_array(groups)) = pstrdup(session.pool,
          gr->gr_name);
      }
    }
  }

  res = 0;
#else
  errno = ENOSYS;
  res = -1;
#endif /* HAVE_GETGROUPLIST */

  return res;
}

static int get_groups_by_getgrent(const char *user, gid_t primary_gid,
    array_header *gids, array_header *groups,
    struct group *(*my_getgrent)(void)) {
  struct group *gr;
  size_t user_len;

  /* This is where things get slow, expensive, and ugly.  Loop through
   * everything, checking to make sure we haven't already added it.
   */
  user_len = strlen(user);
  while ((gr = my_getgrent()) != NULL &&
         gr->gr_mem != NULL) {
    char **gr_member = NULL;

    pr_signals_handle();

    /* Loop through each member name listed */
    for (gr_member = gr->gr_mem; *gr_member; gr_member++) {

     /* If it matches the given username... */
      if (strncmp(*gr_member, user, user_len + 1) == 0) {

        if (gids != NULL &&
            primary_gid != gr->gr_gid) {
          *((gid_t *) push_array(gids)) = gr->gr_gid;
        }

        if (groups != NULL &&
            primary_gid != gr->gr_gid) {
          *((char **) push_array(groups)) = pstrdup(session.pool,
            gr->gr_name);
        }
      }
    }
  }

  return 0;
}

static int get_groups_by_initgroups(const char *user, gid_t primary_gid,
    array_header *gids, array_header *groups,
    struct group *(*my_getgrgid)(gid_t)) {
  int res;
#if defined(HAVE_INITGROUPS) && defined(HAVE_GETGROUPS)
  gid_t group_ids[NGROUPS_MAX+1];
  int ngroups, use_initgroups = TRUE, xerrno;
  register int i;

  /* On Mac OSX, the getgroups(2) man page has this unsettling tidbit:
   *
   *  Calling initgroups(3) to opt-in for supplementary groups will cause
   *  getgroups() to return a single entry, the GID that was passed to
   *  initgroups(3).
   *
   * But in our case, we WANT all of those groups.  Thus on Mac OSX, we
   * will skip the use of initgroups(3) in favor of other mechanisms
   * (e.g. getgrouplist(3)).
   */
# if defined(DARWIN10) || \
     defined(DARWIN11) || \
     defined(DARWIN12) || \
     defined(DARWIN13) || \
     defined(DARWIN14) || \
     defined(DARWIN15)
  use_initgroups = FALSE;
# endif /* Mac OSX */

  /* Use of initgroups(3) might have been disabled via the "NoInitgroups"
   * AuthUnixOption as well.
   */
  if (auth_unix_opts & AUTH_UNIX_OPT_NO_INITGROUPS) {
    use_initgroups = FALSE;
  }

  /* If we are not root, then initgroups(3) will most likely fail. */
  if (geteuid() != PR_ROOT_UID) {
    use_initgroups = FALSE;
  }

  if (use_initgroups == FALSE) {
    errno = ENOSYS;
    return -1;
  }

  pr_trace_msg("auth", 4,
    "using initgroups(3) to look up group membership");

  PRIVS_ROOT
  res = initgroups(user, primary_gid);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (res < 0) {
    pr_log_pri(PR_LOG_WARNING, "initgroups(3) error: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  ngroups = getgroups(NGROUPS_MAX+1, group_ids);
  if (ngroups < 0) {
    xerrno = errno;

    pr_log_pri(PR_LOG_WARNING, "getgroups(2) error: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  for (i = 0; i < ngroups; i++) {
    struct group *gr;

    gr = my_getgrgid(group_ids[i]);
    if (gr != NULL) {
      if (gids != NULL &&
          primary_gid != gr->gr_gid) {
        *((gid_t *) push_array(gids)) = gr->gr_gid;
      }

      if (groups != NULL &&
          primary_gid != gr->gr_gid) {
        *((char **) push_array(groups)) = pstrdup(session.pool,
          gr->gr_name);
      }
    }
  }

  res = 0;

#else
  errno = ENOSYS;
  res = -1;
#endif /* HAVE_INITGROUPS and HAVE_GETGROUPS */

  return res;
}

/* cmd->argv[0] = name
 * cmd->argv[1] = (array_header **) group_ids
 * cmd->argv[2] = (array_header **) group_names
 */
MODRET pw_getgroups(cmd_rec *cmd) {
  int res;
  struct passwd *pw = NULL;
  struct group *gr = NULL;
  array_header *gids = NULL, *groups = NULL;
  const char *name = NULL;

  /* Function pointers for which lookup functions to use */
  struct passwd *(*my_getpwnam)(const char *) = NULL;
  struct group *(*my_getgrgid)(gid_t) = NULL;
  struct group *(*my_getgrent)(void) = NULL;
  RETSETGRENTTYPE (*my_setgrent)(void) = NULL;

  /* Play function pointer games */
  if (unix_persistent_passwd) {
    my_getpwnam = p_getpwnam;
    my_getgrgid = p_getgrgid;
    my_getgrent = p_getgrent;
    my_setgrent = p_setgrent;

  } else {
    my_getpwnam = getpwnam;
    my_getgrgid = getgrgid;
    my_getgrent = getgrent;
    my_setgrent = setgrent;
  }

  name = cmd->argv[0];

  if (cmd->argv[1] != NULL) {
    gids = (array_header *) cmd->argv[1];
  }

  if (cmd->argv[2] != NULL) {
    groups = (array_header *) cmd->argv[2];
  }

  /* Retrieve the necessary info. */
  if (name == NULL ||
      !(pw = my_getpwnam(name))) {
    return PR_DECLINED(cmd);
  }

  /* Populate the first group ID and name. */
  if (gids != NULL) {
    *((gid_t *) push_array(gids)) = pw->pw_gid;
  }

  if (groups != NULL &&
      (gr = my_getgrgid(pw->pw_gid)) != NULL) {
    *((char **) push_array(groups)) = pstrdup(session.pool, gr->gr_name);
  }

  my_setgrent();

  /* Myriad are the ways of obtaining the group membership of a user. */

  res = get_groups_by_initgroups(name, pw->pw_gid, gids, groups, my_getgrgid);
  if (res < 0 &&
      errno == ENOSYS) {
    res = get_groups_by_getgrouplist(name, pw->pw_gid, gids, groups,
      my_getgrgid);
  }

  if (res < 0 &&
      errno == ENOSYS) {
    res = get_groups_by_getgrset(name, pw->pw_gid, gids, groups, my_getgrgid);
  }

  if (res < 0 &&
      errno == ENOSYS) {
    res = get_groups_by_getgrent(name, pw->pw_gid, gids, groups, my_getgrent);
  }

  if (res < 0) {
    return PR_DECLINED(cmd);
  }

  if (gids != NULL &&
      gids->nelts > 0) {
    return mod_create_data(cmd, (void *) &gids->nelts);

  } else if (groups != NULL &&
             groups->nelts > 0) {
    return mod_create_data(cmd, (void *) &groups->nelts);
  }

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

/* usage: AuthUnixOptions opt1 ... */
MODRET set_authunixoptions(cmd_rec *cmd) {
  config_rec *c;
  register unsigned int i;
  unsigned long opts = 0UL;

  if (cmd->argc == 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "AIXNoRLogin") == 0) {
      opts |= AUTH_UNIX_OPT_AIX_NO_RLOGIN;

    } else if (strcasecmp(cmd->argv[i], "NoGetgrouplist") == 0) {
      opts |= AUTH_UNIX_OPT_NO_GETGROUPLIST;

    } else if (strcasecmp(cmd->argv[i], "NoInitgroups") == 0) {
      opts |= AUTH_UNIX_OPT_NO_INITGROUPS;

    } else if (strcasecmp(cmd->argv[i], "MagicTokenChroot") == 0) {
      opts |= AUTH_UNIX_OPT_MAGIC_TOKEN_CHROOT;

    } else if (strcasecmp(cmd->argv[i], "AIXNoAuthenticate") == 0) {
      opts |= AUTH_UNIX_OPT_AIX_NO_AUTHENTICATE;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown AuthUnixOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

MODRET set_persistentpasswd(cmd_rec *cmd) {
  int persistence = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  persistence = get_boolean(cmd, 1);
  if (persistence == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = persistence;

  return PR_HANDLED(cmd);
}

/* Events handlers
 */

static void auth_unix_exit_ev(const void *event_data, void *user_data) {
  pr_auth_endpwent(session.pool);
  pr_auth_endgrent(session.pool);
}

static void auth_unix_sess_reinit_ev(const void *event_data, void *user_data) {
  int res;

  /* A HOST command changed the main_server pointer, reinitialize ourselves. */

  pr_event_unregister(&auth_unix_module, "core.exit", auth_unix_exit_ev);
  pr_event_unregister(&auth_unix_module, "core.session-reinit",
    auth_unix_sess_reinit_ev);
  auth_unix_opts = 0UL;
  unix_persistent_passwd = FALSE;

  res = auth_unix_sess_init();
  if (res < 0) {
    pr_session_disconnect(&auth_unix_module,
      PR_SESS_DISCONNECT_SESSION_INIT_FAILED, NULL);
  }
}

/* Initialization routines
 */

static int auth_unix_init(void) {

#ifdef HAVE__PW_STAYOPEN
  _pw_stayopen = 1;
#endif

  return 0;
}

static int auth_unix_sess_init(void) {
  config_rec *c;

  pr_event_register(&auth_unix_module, "core.exit", auth_unix_exit_ev, NULL);
  pr_event_register(&auth_unix_module, "core.session-reinit",
    auth_unix_sess_reinit_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "AuthUnixOptions", FALSE);
  if (c) {
    auth_unix_opts = *((unsigned long *) c->argv[0]);
  }

  c = find_config(main_server->conf, CONF_PARAM, "PersistentPasswd", FALSE);
  if (c) {
    unix_persistent_passwd = *((int *) c->argv[0]);
  }
 
  return 0;
}

/* Module API tables
 */

static conftable auth_unix_conftab[] = {
  { "AuthUnixOptions",		set_authunixoptions,		NULL },
  { "PersistentPasswd",		set_persistentpasswd,		NULL },
  { NULL,			NULL,				NULL }
};

static authtable auth_unix_authtab[] = {
  { 0,  "setpwent",	pw_setpwent },
  { 0,  "endpwent",	pw_endpwent },
  { 0,  "setgrent",     pw_setgrent },
  { 0,  "endgrent",	pw_endgrent },
  { 0,	"getpwent",	pw_getpwent },
  { 0,  "getgrent",	pw_getgrent },
  { 0,  "getpwnam",	pw_getpwnam },
  { 0,	"getpwuid",	pw_getpwuid },
  { 0,  "getgrnam",     pw_getgrnam },
  { 0,  "getgrgid",     pw_getgrgid },
  { 0,  "auth",         pw_auth	},
  { 0,  "authorize",	pw_authz },
  { 0,  "check",	pw_check },
  { 0,  "uid2name",	pw_uid2name },
  { 0,  "gid2name",	pw_gid2name },
  { 0,  "name2uid",	pw_name2uid },
  { 0,  "name2gid",	pw_name2gid },
  { 0,  "getgroups",	pw_getgroups },
  { 0,  NULL }
};

module auth_unix_module = {
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "auth_unix",

  /* Module configuration handler table */
  auth_unix_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  auth_unix_authtab,

  /* Module initialization */
  auth_unix_init,

  /* Session initialization */
  auth_unix_sess_init
};
