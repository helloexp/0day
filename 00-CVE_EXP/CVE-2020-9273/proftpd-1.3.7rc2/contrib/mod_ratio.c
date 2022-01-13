/*
 * ProFTPD: mod_ratio -- Support upload/download ratios.
 * Portions Copyright (c) 1998-1999 Johnie Ingram.
 * Copyright (c) 2002 James Dogopoulos.
 * Copyright (c) 2008-2017 The ProFTPD Project team
 *  
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 */

#define MOD_RATIO_VERSION "mod_ratio/3.3"

/* This is mod_ratio, contrib software for proftpd 1.2.0 and above.
   For more information contact James Dogopoulos <jd@dynw.com> or
   Johnie Ingram <johnie@netgod.net>.

   History Log:

   * 2002-05-24: v3.3: Fixed numerous bugs and compatibility issues with
     changing code within ProFTPD. In other words, it /works/ again!
     Added default AnonRatio support (AnonRatio * ...).

   * 2000-08-01: v3.2: Fixed CwdRatio directive. Ratios are no longer part
     of CWD or NOOP commands. Fixed file byte ratio printing. It is now
     UL:DL - the way it should be. Updated README.ratio file. - jD

   * 2000-02-15: v3.1: Added support to save user stats to plain text file.
     (See README.ratio) Changed display to MBytes rather than Bytes. Tracks
     to the nearest Kilobyte rather than byte. - jD

   * 1999-10-03: v3.0: Uses generic API to access SQL data at runtime.
     Supports negative ratios (upload X to get 1) by popular demand.
     Added proper SITE command and help.  Various presentation
     idiosyncracies fixed.

   * 1999-06-13: v2.2: fixed ratio display, it was printing ratios in
     reverse order.

   * 1999-05-03: v2.1: mod_mysql bugfix; rearranged CWD reply so
     Netscape shows ratios; fixed recalculation in XRATIO.  Added
     CwdRatioMsg directive for showing equivalent URLs (always
     enabled).
   
   * 1999-04-08: v2.0: Reformat and rewrite.  Add FileRatioErrMsg,
     ByteRatioErrMsg, and LeechRatioMsg directives and support for
     proftpd mod_mysql.

   * 1998-09-08: v1.0: Accepted into CVS as a contrib module.

*/

#include "conf.h"

int gotratuser,fileerr;

static struct
{
  int fstor, fretr, frate, fcred, brate, bcred;
  int files;

  off_t bstor, bretr; 
  off_t bytes;

  char ftext [64],btext [64];

} stats;

static struct
{
  int enable;
  int save;
  char user [PR_TUNABLE_LOGIN_MAX];

  const char *rtype;          /* The ratio type currently in effect. */

  const char *filemsg;
  const char *bytemsg;
  const char *leechmsg;
  const char *ratiofile;
  const char *ratiotmp;
} g;

#define RATIO_ENFORCE (stats.frate || stats.brate)

#define RATIO_STUFFS "-%d/%lu +%d/%lu (%d %d %d %d) = %d/%lu%s%s", \
	    stats.fretr, (unsigned long) (stats.bretr / 1024), \
            stats.fstor, (unsigned long) (stats.bstor / 1024), \
            stats.frate, stats.fcred, stats.brate, stats.bcred, \
            stats.files, (unsigned long) (stats.bytes / 1024), \
	    (stats.frate && stats.files < 1) ? " [NO F]" : "", \
	    (stats.brate && (stats.bytes / 1024) < 5) ? " [LO B]" : ""
#define SHORT_RATIO_STUFFS "-%d/%lu +%d/%lu = %d/%lu%s%s", \
	    stats.fretr, (unsigned long) (stats.bretr / 1024), \
            stats.fstor, (unsigned long) (stats.bstor / 1024), \
            stats.files, (unsigned long) (stats.bytes / 1024), \
	    (stats.frate && stats.files < 1) ? " [NO F]" : "", \
	    (stats.brate && (stats.bytes / 1024) < 5) ? " [LO B]" : ""

static cmd_rec *
_make_cmd (pool * cp, int argc, ...)
{
  va_list args;
  cmd_rec *c;
  int i;

  pool *newpool = NULL;
  newpool = make_sub_pool( cp );
  c = pcalloc(newpool, sizeof(cmd_rec));

  c->pool = newpool;
  c->argv = pcalloc(newpool, sizeof(void *) * (argc + 1));

  c->argc = argc;
  c->stash_index = -1;

  c->argv[0] = MOD_RATIO_VERSION;
  va_start (args, argc);
  for (i = 0; i < argc; i++)
    c->argv[i + 1] = (void *) va_arg (args, char *);
  va_end (args);

  return c;
}

static modret_t *
_dispatch_ratio (cmd_rec * cmd, char *match)
{
  authtable *m;
  modret_t *mr = NULL;

  m = pr_stash_get_symbol2 (PR_SYM_AUTH, match, NULL, &cmd->stash_index,
    &cmd->stash_hash);
  while (m)
    {
      mr = pr_module_call (m->m, m->handler, cmd);
      if (MODRET_ISHANDLED (mr) || MODRET_ISERROR (mr))
	break;
      m = pr_stash_get_symbol2 (PR_SYM_AUTH, match, m, &cmd->stash_index,
        &cmd->stash_hash);
    }

  if (MODRET_ISERROR(mr))
      pr_log_debug(DEBUG0, MOD_RATIO_VERSION ": internal error: %s",
          MODRET_ERRMSG(mr));

  return mr;
}

static modret_t *
_dispatch (cmd_rec * cmd, char *match)
{
  cmd_rec *cr;
  modret_t *mr = 0;

  cr = _make_cmd (cmd->tmp_pool, 0);
  mr = _dispatch_ratio (cr, match);
  if (cr->tmp_pool)
    destroy_pool (cr->tmp_pool);
  return mr;
}

static void
set_stats (const char *fstor, const char *fretr, const char *bstor,
  const char *bretr)
{

  if (fstor)
    stats.fstor = atoi(fstor);

  if (fretr)
    stats.fretr = atoi(fretr);

#ifdef HAVE_STRTOULL
  if (bstor) {
    char *tmp = NULL;
    off_t res;

    res = strtoull(bstor, &tmp, 10);
    if (tmp == NULL) 
      stats.bstor = res;
  }

  if (bretr) {
    char *tmp = NULL;
    off_t res;

    res = strtoull(bretr, &tmp, 10);
    if (tmp == NULL)
      stats.bretr = res;
  }
#else
  if (bstor) {
    char *tmp = NULL;
    off_t res;

    res = strtoul(bstor, &tmp, 10);
    if (tmp == NULL) 
      stats.bstor = res;
  }
    
  if (bretr) {
    char *tmp = NULL;
    off_t res;

    res = strtoul(bretr, &tmp, 10);
    if (tmp == NULL)
      stats.bretr = res;
  }
#endif /* HAVE_STRTOULL */
}

static void update_ratios(const char *frate, const char *fcred,
    const char *brate, const char *bcred) {
  stats.frate = stats.fcred = stats.brate = stats.bcred = 0;

  if (frate)
    stats.frate = atoi (frate);
  if (fcred)
    stats.fcred = atoi (fcred);
  if (brate)
    stats.brate = atoi (brate);
  if (bcred)
    stats.bcred = atoi (bcred);

  if (stats.frate >= 0)
    {
      stats.files = (stats.frate * stats.fstor) + stats.fcred - stats.fretr;
      memset(stats.ftext, '\0', sizeof(stats.ftext));
      pr_snprintf (stats.ftext, sizeof(stats.ftext)-1, "1:%dF", stats.frate);
    }
  else
    {
      stats.files = (stats.fstor / (stats.frate * -1)) + stats.fcred - stats.fretr;
      memset(stats.ftext, '\0', sizeof(stats.ftext));
      pr_snprintf (stats.ftext, sizeof(stats.ftext)-1, "%d:1F", stats.frate * -1);
    }

  if (stats.brate >= 0)
    {
      stats.bytes = (stats.brate * stats.bstor) + stats.bcred - stats.bretr;
      memset(stats.btext, '\0', sizeof(stats.btext));
      pr_snprintf (stats.btext, sizeof(stats.btext)-1, "1:%dB", stats.brate);
    }
  else
    {
      stats.bytes = (stats.bstor / (stats.brate * -1)) + stats.bcred - stats.bretr;
      memset(stats.btext, '\0', sizeof(stats.btext));
      pr_snprintf (stats.btext, sizeof(stats.btext)-1, "%d:1B", stats.brate * -1);
    }
}


MODRET calc_ratios (cmd_rec * cmd)
{
  modret_t *mr = 0;
  config_rec *c;
  char buf[1024] = {'\0'};
  char *mask;
  char **data;
  void *ptr;

  ptr = get_param_ptr (main_server->conf, "Ratios", FALSE);
  if (ptr)
    g.enable = *((int *) ptr);

  if (!g.enable)
    return PR_DECLINED (cmd);

  mr = _dispatch (cmd, "getstats");
  if (MODRET_HASDATA (mr))
    {
      data = mr->data;
      if (data[4])
	pr_log_debug(DEBUG4, MOD_RATIO_VERSION
          ": warning: getstats on %s not unique", g.user);
      set_stats (data[0], data[1], data[2], data[3]);
    }

  mr = _dispatch (cmd, "getratio");
  if (MODRET_HASDATA (mr))
    {
      data = mr->data;
      if (data[4])
	pr_log_debug(DEBUG4, MOD_RATIO_VERSION
          ": warning: getratio on %s not unique", g.user);
      update_ratios(data[0], data[1], data[2], data[3]);
      g.rtype = "U";
      return PR_DECLINED (cmd);
    }

  c = find_config (main_server->conf, CONF_PARAM, "HostRatio", TRUE);
  while (c)
    {
     mask = buf;
      if (*(char *) c->argv[0] == '.')
	{
	  *mask++ = '*';
	  sstrncpy (mask, c->argv[0], sizeof (buf));
	}
      else if (*(char *) ((char *) c->argv[0] + (strlen (c->argv[0]) - 1)) == '.')
	{
	  sstrncpy (mask, c->argv[0], sizeof(buf) - 2);
	  sstrcat(buf, "*", sizeof(buf));
	}
      else
	sstrncpy (mask, c->argv[0], sizeof (buf));

      if (!pr_fnmatch (buf, session.c->remote_name, PR_FNM_NOESCAPE | PR_FNM_CASEFOLD) ||
	  !pr_fnmatch (buf, pr_netaddr_get_ipstr (session.c->remote_addr),
		       PR_FNM_NOESCAPE | PR_FNM_CASEFOLD))
	{
	  update_ratios(c->argv[1], c->argv[2], c->argv[3], c->argv[4]);
	  g.rtype = "h";
	  return PR_DECLINED (cmd);
	}
      c = find_config_next (c, c->next, CONF_PARAM, "HostRatio", FALSE);
    }

  c = find_config (main_server->conf, CONF_PARAM, "AnonRatio", TRUE);
  while (c)
    {
      if ((session.anon_user && !strcmp (c->argv[0], session.anon_user)) ||
		*(char *) c->argv[0] == '*')
	{
	  update_ratios(c->argv[1], c->argv[2], c->argv[3], c->argv[4]);
	  g.rtype = "a";
	  return PR_DECLINED (cmd);
	}
      c = find_config_next (c, c->next, CONF_PARAM, "AnonRatio", FALSE);
    }

  c = find_config (main_server->conf, CONF_PARAM, "UserRatio", TRUE);
  while (c)
    {
      if (*(char *) c->argv[0] == '*' || !strcmp (c->argv[0], g.user))
	{
	  update_ratios(c->argv[1], c->argv[2], c->argv[3], c->argv[4]);
	  g.rtype = "u";
	  return PR_DECLINED (cmd);
	}
      c = find_config_next (c, c->next, CONF_PARAM, "UserRatio", FALSE);
    }

  c = find_config(main_server->conf, CONF_PARAM, "GroupRatio", FALSE);
  while (c) {
    pr_signals_handle();

    if (strcmp(c->argv[0], session.group) == 0) {
      update_ratios(c->argv[1], c->argv[2], c->argv[3], c->argv[4]);
      g.rtype = "g";

      return PR_DECLINED(cmd);

    } else {
      if (session.groups) {
        register unsigned int i;
        char **group_names = session.groups->elts;

        /* Check the list of supplemental groups for this user as well. */
        for (i = 0; i < session.groups->nelts-1; i++) {
          if (strcmp(c->argv[0], group_names[i]) == 0) {
            update_ratios(c->argv[1], c->argv[2], c->argv[3], c->argv[4]);
            g.rtype = "g";

            return PR_DECLINED(cmd);
          }
        }
      } 
    }

    c = find_config_next(c, c->next, CONF_PARAM, "GroupRatio", FALSE);
  }

  return PR_DECLINED (cmd);
}

static void
log_ratios (cmd_rec * cmd)
{
  char buf[1024] = {'\0'};

  memset(buf, '\0', sizeof(buf));
  pr_snprintf (buf, sizeof(buf)-1, SHORT_RATIO_STUFFS);
  pr_log_debug(DEBUG0, MOD_RATIO_VERSION ": %s in %s: %s %s%s%s", g.user,
    session.cwd, cmd->argv[0], cmd->arg, RATIO_ENFORCE ? " :" : "",
    RATIO_ENFORCE ? buf : "");
}

static void
update_stats (void)
{
    FILE *usrfile = NULL, *newfile = NULL;
    char usrstr[256] = {'\0'}, *ratname;
    int ulfiles,dlfiles,cpc;
    off_t ulbytes = 0, dlbytes = 0;

    if (!fileerr) {
        newfile = fopen(g.ratiotmp, "w");
        if (newfile == NULL) {
            pr_log_debug(DEBUG3, MOD_RATIO_VERSION
                ": error opening temporary ratios file '%s': %s", g.ratiotmp,
                strerror(errno));
            gotratuser = 1;
            fileerr = 1;
            return;
        }
    }

    usrfile = fopen(g.ratiofile, "r");

    if (usrfile != NULL) {
        while (fgets(usrstr, sizeof(usrstr), usrfile) != NULL) {
            char *tok = NULL;

            pr_signals_handle();

            tok = strtok(usrstr, "|");
            ratname = tok;

            tok = strtok(NULL, "|");
            ulfiles = atoi(tok);

            tok = strtok(NULL, "|");
            if (tok) {
                char *tmp = NULL;
                off_t res;

#ifdef HAVE_STRTOULL
                res = strtoull(tok, &tmp, 10);
#else
                res = strtoul(tok, &tmp, 10);
#endif /* HAVE_STRTOULL */

                if (tmp == NULL)
                    ulbytes = res;
            }

            tok = strtok(NULL, "|");
            dlfiles = atoi(tok);

            tok = strtok(NULL, "|");
            if (tok) {
                char *tmp = NULL;
                off_t res;

#ifdef HAVE_STRTOULL
                res = strtoull(tok, &tmp, 10);
#else
                res = strtoul(tok, &tmp, 10);
#endif /* HAVE_STRTOULL */

                if (tmp == NULL)
                    dlbytes = res;
            }

            if (strcmp(ratname, g.user) == 0) {
                fprintf(newfile, "%s|%d|%" PR_LU "|%d|%" PR_LU "\n", g.user,
                    stats.fstor, (pr_off_t) stats.bstor, stats.fretr,
                    (pr_off_t) stats.bretr);

            } else {
                fprintf(newfile, "%s|%d|%" PR_LU "|%d|%" PR_LU "\n", ratname,
                    ulfiles, (pr_off_t) ulbytes, dlfiles, (pr_off_t) dlbytes);
            }
        }

    } else {
        pr_log_debug(DEBUG3, MOD_RATIO_VERSION
            ": error opening ratios file '%s': %s", g.ratiofile,
            strerror(errno));
        gotratuser = 1;
        fileerr = 1;
    }

    if (usrfile)
        fclose(usrfile);

    if (newfile)
        fclose(newfile);

    newfile = fopen(g.ratiotmp, "rb");
    if (newfile == NULL) {
        pr_log_debug(DEBUG3, MOD_RATIO_VERSION
            ": error opening temporary ratios file '%s': %s", g.ratiotmp,
            strerror(errno));
    }

    usrfile = fopen(g.ratiofile, "wb");
    if (usrfile == NULL) {
        pr_log_debug(DEBUG3, MOD_RATIO_VERSION
            ": error opening ratios file '%s': %s", g.ratiofile,
            strerror(errno));
    }

    if (newfile != NULL &&
        usrfile != NULL) {

        while ((cpc = getc(newfile)) != EOF) {
            pr_signals_handle();
            putc(cpc, usrfile);
        }
    }

    if (usrfile)
        fclose(usrfile);

    if (newfile)
        fclose(newfile);
}

MODRET
pre_cmd_retr (cmd_rec * cmd)
{
  char *path;
  int fsize = 0;
  struct stat sbuf;

  calc_ratios (cmd);
  if (!g.enable)
    return PR_DECLINED (cmd);
  log_ratios (cmd);

  if (!RATIO_ENFORCE)
    return PR_DECLINED (cmd);

  if (stats.frate && stats.files < 1)
    {
      pr_response_add_err (R_550, "%s", g.filemsg);
      pr_response_add_err (R_550,
			"%s: FILE RATIO: %s  Down: %d  Up: only %d!",
			cmd->arg, stats.ftext, stats.fretr, stats.fstor);
      return PR_ERROR (cmd);
    }

  if (stats.brate)
    {
      path = dir_realpath (cmd->tmp_pool, cmd->arg);
      if (path
	  && dir_check (cmd->tmp_pool, cmd, cmd->group, path, NULL)
	  && pr_fsio_stat (path, &sbuf) > -1)
	fsize = sbuf.st_size;

      if ((stats.bytes - (fsize / 1024)) < 0)
	{
	  pr_response_add_err (R_550, "%s", g.bytemsg);
	  pr_response_add_err (R_550,
              "%s: BYTE RATIO: %s  Down: %lumb  Up: only %lumb!", cmd->arg,
              stats.btext, (unsigned long) (stats.bretr / 1024),
              (unsigned long) (stats.bstor / 1024));
	  return PR_ERROR (cmd);
	}
    }

  return PR_DECLINED (cmd);
}

MODRET ratio_log_pass(cmd_rec *cmd) {
  if (session.anon_user) {
    sstrncpy(g.user, session.anon_user, sizeof(g.user));
  }

  calc_ratios (cmd);
  if (g.enable) {
    char buf[256];

    memset(buf, '\0', sizeof(buf));
    pr_snprintf(buf, sizeof(buf)-1, RATIO_STUFFS);
    pr_log_pri(PR_LOG_INFO, "Ratio: %s/%s %s[%s]: %s.", g.user,
      session.group, session.c->remote_name, pr_netaddr_get_ipstr
      (session.c->remote_addr), buf);
  }

  return PR_DECLINED (cmd);
}

MODRET
pre_cmd (cmd_rec * cmd)
{
  if (g.enable)
    {
    /*  if (!strcasecmp (cmd->argv[0], "STOR")) */
      if (strcasecmp (cmd->argv[0], "STOR") || strcasecmp(cmd->argv[0], "RETR"))
	calc_ratios (cmd);
      log_ratios (cmd);
    }
  return PR_DECLINED (cmd);
}

MODRET
cmd_cwd (cmd_rec * cmd)
{
  char *dir;
  config_rec *c = find_config (main_server->conf, CONF_PARAM, "CwdRatioMsg", TRUE);
  if (c)
    {
      dir = dir_realpath (cmd->tmp_pool, cmd->argv[1]);
      while (dir && c)
	{
	  if (!*((char *) c->argv[0]))
	    return PR_DECLINED (cmd);
	  pr_response_add (R_250, "%s", (char *) c->argv[0]);
	  c = find_config_next (c, c->next, CONF_PARAM, "CwdRatioMsg", FALSE);
	}
    }
  return PR_DECLINED (cmd);
}

MODRET ratio_post_cmd(cmd_rec *cmd) {
  FILE *usrfile = NULL, *newfile = NULL;
  char sbuf1[128] = {'\0'}, sbuf2[128] = {'\0'},
       sbuf3[128] = {'\0'}, usrstr[256] = {'\0'};
  char *ratname;
  int ulfiles,dlfiles,cpc;
  off_t ulbytes = 0, dlbytes = 0;

  if (!gotratuser && g.save) {
	usrfile = fopen(g.ratiofile, "r");
	if (usrfile == NULL) {
	    pr_log_debug(DEBUG3, MOD_RATIO_VERSION
                ": error opening ratios file '%s': %s", g.ratiofile,
                strerror(errno));
	    gotratuser = 1;
	    fileerr = 1;
        }
  }

  if (session.anon_user)
     sstrncpy(g.user, session.anon_user, sizeof(g.user));

  if (strlen(g.user) == 0)
     sstrncpy(g.user, "NOBODY", sizeof(g.user));

  if (!gotratuser && !fileerr && g.save) {
      if (!usrfile)
          usrfile = fopen(g.ratiofile, "r");

      if (usrfile) {
          while (fgets(usrstr, sizeof(usrstr), usrfile) != NULL) {
              char *tok = NULL;

              pr_signals_handle();

              tok = strtok(usrstr, "|");
              ratname = tok;

              tok = strtok(NULL, "|");
              ulfiles = atoi(tok);

              tok = strtok(NULL, "|");
              if (tok) {
                  char *tmp = NULL;
                  off_t res;

#ifdef HAVE_STRTOULL
                  res = strtoull(tok, &tmp, 10);
#else
                  res = strtoul(tok, &tmp, 10);
#endif /* HAVE_STRTOULL */

                  if (tmp == NULL)
                      ulbytes = res;
              }

              tok = strtok(NULL, "|");
              dlfiles = atoi(tok);

              tok = strtok(NULL, "|");
              if (tok) {
                  char *tmp = NULL;
                  off_t res;

#ifdef HAVE_STRTOULL
                  res = strtoull(tok, &tmp, 10);
#else
                  res = strtoul(tok, &tmp, 10);
#endif /* HAVE_STRTOULL */

                  if (tmp == NULL)
                      dlbytes = res;
              }

              if (strcmp(ratname, g.user) == 0) {
                  stats.fretr += dlfiles;
                  stats.bretr += dlbytes;
                  stats.fstor += ulfiles;
                  stats.bstor += ulbytes;
                  gotratuser = 1;
              }
          }
          fclose(usrfile);

      } else {
          pr_log_debug(DEBUG3, MOD_RATIO_VERSION
              ": error opening ratios file '%s': %s", g.ratiofile,
              strerror(errno));
          gotratuser = 1;
          fileerr = 1;
      }

      /* Entry for user must not exist, create... */
      if (!gotratuser && !fileerr) {
          newfile = fopen(g.ratiotmp, "w");
          if (newfile == NULL) {
              pr_log_debug(DEBUG3, MOD_RATIO_VERSION
                  ": error opening temporary ratios file '%s': %s",
                  g.ratiotmp, strerror(errno));
              gotratuser = 1;
              fileerr = 1;
          }
      }

      if (!gotratuser && !fileerr) {
          usrfile = fopen(g.ratiofile, "r");
          if (usrfile) {

              /* Copy the existing lines into the temporary file. */
              while (fgets(usrstr, sizeof(usrstr), usrfile) != NULL) {
                  pr_signals_handle();
                  fprintf(newfile, "%s", usrstr);
              }

              fprintf(newfile, "%s|%d|%" PR_LU "|%d|%" PR_LU "\n", g.user,
                  stats.fstor, (pr_off_t) stats.bstor, stats.fretr,
                  (pr_off_t) stats.bretr);

              fclose(usrfile);
              fclose(newfile);

              /* Copy the temporary file to the actual file. */
              newfile = fopen(g.ratiotmp, "rb");
              usrfile = fopen(g.ratiofile, "wb");

              if (newfile != NULL &&
                  usrfile != NULL) {

                  while ((cpc = getc(newfile)) != EOF) {
                      pr_signals_handle();
                      putc(cpc, usrfile);
                  }
              }

              if (usrfile)
                  fclose(usrfile);

              if (newfile)
                  fclose(newfile);
          }
      }
  }

  if (g.enable) {
      int cwding = !strcasecmp (cmd->argv[0], "CWD");
    char *r = (cwding) ? R_250 : R_DUP;
      sbuf1[0] = sbuf2[0] = sbuf3[0] = 0;
      if (cwding || !strcasecmp (cmd->argv[0], "PASS"))
	calc_ratios (cmd);

      pr_snprintf(sbuf1, sizeof(sbuf1), "Down: %d Files (%lumb)  Up: %d Files (%lumb)",
	stats.fretr, (unsigned long) (stats.bretr / 1024),
        stats.fstor, (unsigned long) (stats.bstor / 1024));
      if (stats.frate)
	pr_snprintf (sbuf2, sizeof(sbuf2),
		  "   %s CR: %d", stats.ftext, stats.files);
      if (stats.brate)
	pr_snprintf (sbuf3, sizeof(sbuf3), "   %s CR: %lu", stats.btext,
          (unsigned long) (stats.bytes / 1024));

      if (RATIO_ENFORCE)
	{
	  pr_response_add (r, "%s%s%s", sbuf1, sbuf2, sbuf3);
	  if (stats.frate && stats.files < 0)
	    pr_response_add (r, "%s", g.filemsg);
	  if (stats.brate && stats.bytes < 0)
	    pr_response_add (r, "%s", g.bytemsg);
	}
      else
	pr_response_add (r, "%s%s%s", sbuf1, g.leechmsg ? "  " : "", g.leechmsg);
  }

  return PR_DECLINED(cmd);
}

MODRET
cmd_site (cmd_rec * cmd)
{
  char buf[128] = {'\0'};
  
  if (cmd->argc < 2)
    return PR_DECLINED(cmd);
  
  if (strcasecmp(cmd->argv[1], "RATIO") == 0) {
    calc_ratios(cmd);
    pr_snprintf(buf, sizeof(buf), RATIO_STUFFS);
    pr_response_add(R_214, "Current Ratio: ( %s )", buf);
    if(stats.frate)
      pr_response_add(R_214,
		   "Files: %s  Down: %d  Up: %d  CR: %d file%s",
		   stats.ftext, stats.fretr, stats.fstor,
		   stats.files, (stats.files != 1) ? "s" : "");
    if(stats.brate)
      pr_response_add(R_214,
		   "Bytes: %s  Down: %lumb  Up: %lumb  CR: %lu Mbytes",
		   stats.btext, (unsigned long) (stats.bretr / 1024),
                   (unsigned long) (stats.bstor / 1024),
                   (unsigned long) (stats.bytes / 1024));
    return PR_HANDLED(cmd);
  }
  
  if (strcasecmp (cmd->argv[1], "HELP") == 0) {
    pr_response_add(R_214,
		 "The following SITE extensions are recognized:");
    pr_response_add(R_214, "RATIO " "-- show all ratios in effect");
  }
  
  return PR_DECLINED (cmd);
}

/* FIXME: because of how ratio and sql interact, the status sent after
   STOR and RETR commands is always out-of-date.  Reorder module loading?  */

MODRET ratio_post_retr(cmd_rec *cmd) {
  stats.fretr++;
  stats.bretr += (session.xfer.total_bytes / 1024);

  calc_ratios (cmd);

  if (!fileerr && g.save) {
      update_stats ();
  }

  return ratio_post_cmd(cmd);
}

MODRET ratio_post_stor(cmd_rec *cmd) {
  stats.fstor++;
  stats.bstor += (session.xfer.total_bytes / 1024);

  calc_ratios (cmd);

  if (!fileerr && g.save) {
      update_stats ();
  }

  return ratio_post_cmd(cmd);
}

MODRET
cmd_user (cmd_rec * cmd)
{
  if (!g.user[0])
    sstrncpy (g.user, cmd->argv[1], PR_TUNABLE_LOGIN_MAX);
  return PR_DECLINED (cmd);
}

/* **************************************************************** */

MODRET
add_ratiodata (cmd_rec * cmd)
{
  CHECK_ARGS (cmd, 5);
  CHECK_CONF (cmd,
	      CONF_ROOT | CONF_VIRTUAL | CONF_ANON | CONF_DIR | CONF_GLOBAL);
  add_config_param_str (cmd->argv[0], 5, (void *) cmd->argv[1],
			(void *) cmd->argv[2], (void *) cmd->argv[3],
			(void *) cmd->argv[4], (void *) cmd->argv[5]);
  return PR_HANDLED (cmd);
}

MODRET set_ratios(cmd_rec *cmd) {
  int bool;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON|CONF_DIR);

  bool = get_boolean(cmd, 1);
  if (bool == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;
  c->flags |= CF_MERGEDOWN;

  return PR_HANDLED(cmd);
}

MODRET
add_saveratios (cmd_rec * cmd)
{
  int b;
  config_rec *c;

  CHECK_ARGS (cmd, 1);
  CHECK_CONF (cmd, CONF_ROOT | CONF_VIRTUAL
              | CONF_ANON | CONF_DIR | CONF_GLOBAL);
  b = get_boolean (cmd, 1);
  if (b == -1)
    CONF_ERROR (cmd, "requires a boolean value");
  c = add_config_param (cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;
  c->flags |= CF_MERGEDOWN;
  return PR_HANDLED (cmd);
}

MODRET
add_str (cmd_rec * cmd)
{
  CHECK_ARGS (cmd, 1);
  CHECK_CONF (cmd, CONF_ROOT | CONF_VIRTUAL
	      | CONF_ANON | CONF_DIR | CONF_GLOBAL);
  add_config_param_str (cmd->argv[0], 1, (void *) cmd->argv[1]);
  return PR_HANDLED (cmd);
}

/* **************************************************************** */

static int ratio_sess_init(void) {
  void *ptr;

  memset(&g, 0, sizeof (g));

  ptr = get_param_ptr(TOPLEVEL_CONF, "Ratios", FALSE);
  if (ptr) {
    g.enable = *((int *) ptr);
  }

  ptr = get_param_ptr (TOPLEVEL_CONF, "SaveRatios", FALSE);
  if (ptr)
    g.save = *((int *) ptr);

  if (!(g.filemsg = get_param_ptr (TOPLEVEL_CONF, "FileRatioErrMsg", FALSE)))
    g.filemsg = "Too few files uploaded to earn file -- please upload more.";

  if (!(g.ratiofile = get_param_ptr (TOPLEVEL_CONF, "RatioFile", FALSE)))
    g.ratiofile = "";

  if (!(g.ratiotmp = get_param_ptr (TOPLEVEL_CONF, "RatioTempFile", FALSE)))
    g.ratiotmp = "";

  if (!(g.bytemsg = get_param_ptr (TOPLEVEL_CONF, "ByteRatioErrMsg", FALSE)))
    g.bytemsg = "Too few bytes uploaded to earn more data -- please upload.";

  if (!(g.leechmsg = get_param_ptr (TOPLEVEL_CONF, "LeechRatioMsg", FALSE)))
    g.leechmsg = "10,000,000:1  CR: LEECH";

  return 0;
}

/* Module API tables
 */

static cmdtable ratio_cmdtab[] = {
  { PRE_CMD,  C_CWD,	G_NONE, pre_cmd, 	FALSE, FALSE },
  { CMD,      C_CWD,	G_NONE, cmd_cwd, 	FALSE, FALSE },

  { PRE_CMD,  C_LIST,	G_NONE, pre_cmd, 	FALSE, FALSE },
  { POST_CMD, C_LIST,	G_NONE, ratio_post_cmd,	FALSE, FALSE },

  { PRE_CMD,  C_NLST,	G_NONE, pre_cmd, 	FALSE, FALSE },
  { POST_CMD, C_NLST,	G_NONE, ratio_post_cmd,	FALSE, FALSE },

  { PRE_CMD,  C_RETR,   G_NONE, pre_cmd_retr,	FALSE, FALSE },
  { POST_CMD, C_RETR,   G_NONE, ratio_post_retr,FALSE, FALSE },

  { PRE_CMD,  C_STOR,	G_NONE, pre_cmd, 	FALSE, FALSE },
  { POST_CMD, C_STOR,	G_NONE, ratio_post_stor,FALSE, FALSE },

  { CMD,      C_SITE,	G_NONE, cmd_site, 	FALSE, FALSE },

  { CMD,      C_USER,	G_NONE, cmd_user, 	FALSE, FALSE },

  { POST_CMD, C_PASS,	G_NONE, ratio_post_cmd, FALSE, FALSE },
  { LOG_CMD,  C_PASS,	G_NONE, ratio_log_pass, FALSE, FALSE },

  { 0, NULL }
};

static conftable ratio_conftab[] = {
  { "UserRatio",	add_ratiodata,       NULL },
  { "GroupRatio",	add_ratiodata,       NULL },
  { "AnonRatio",	add_ratiodata,       NULL },
  { "HostRatio",	add_ratiodata,       NULL },
  { "Ratios",	        set_ratios,          NULL },

  { "FileRatioErrMsg",	add_str,             NULL },
  { "ByteRatioErrMsg",	add_str,             NULL },
  { "LeechRatioMsg",	add_str,             NULL },
  { "CwdRatioMsg",	add_str,             NULL },
  { "SaveRatios",	add_saveratios,	     NULL },
  { "RatioFile",	add_str,	     NULL },
  { "RatioTempFile",	add_str,	     NULL },

  { NULL, NULL, NULL }
};

module ratio_module = {

  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "ratio",

  /* Module configuration handler table */
  ratio_conftab,

  /* Module command handler table */
  ratio_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  NULL,

  /* Session initialization */
  ratio_sess_init,

  /* Module version */
  MOD_RATIO_VERSION
};
