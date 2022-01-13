/*
 * ProFTPD - mod_sftp Display files
 * Copyright (c) 2010-2017 TJ Saunders
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
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

/* Display of files */

#include "mod_sftp.h"
#include "display.h"
#include "packet.h"
#include "msg.h"

/* Note: The size provided by pr_fs_getsize2() is in KB, not bytes. */
static void format_size_str(char *buf, size_t buflen, off_t size) {
  char *units[] = {"K", "M", "G", "T", "P", "E", "Z", "Y"};
  unsigned int nunits = 8;
  register unsigned int i = 0;
  int res;

  /* Determine the appropriate units label to use. Do not exceed the max
   * possible unit support (yottabytes), by ensuring that i maxes out at
   * index 7 (of 8 possible units).
   */
  while (size > 1024 &&
         i < (nunits - 1)) {
    pr_signals_handle();

    size /= 1024;
    i++;
  }

  /* Now, prepare the buffer. */
  res = pr_snprintf(buf, buflen, "%.3" PR_LU "%sB", (pr_off_t) size, units[i]);
  if (res > 2) {
    /* Check for leading zeroes; it's an aethetic choice. */
    if (buf[0] == '0' && buf[1] != '.') {
      memmove(&buf[0], &buf[1], res-1);
      buf[res-1] = '\0';
    }
  }
}

const char *sftp_display_fh_get_msg(pool *p, pr_fh_t *fh) {
  struct stat st;
  char buf[PR_TUNABLE_BUFFER_SIZE], *msg = "";
  int len, res;
  const unsigned int *current_clients = NULL;
  const unsigned int *max_clients = NULL;
  off_t fs_size = 0;
  const void *v;
  const char *outs, *rfc1413_ident, *user;
  const char *serverfqdn = main_server->ServerFQDN;
  char mg_size[12] = {'\0'}, mg_size_units[12] = {'\0'},
    mg_max[12] = "unlimited";
  char mg_class_limit[12] = {'\0'}, mg_cur[12] = {'\0'},
    mg_cur_class[12] = {'\0'};
  const char *mg_time;

  /* Stat the opened file to determine the optimal buffer size for IO. */
  memset(&st, 0, sizeof(st));
  if (pr_fsio_fstat(fh, &st) == 0) {
    fh->fh_iosz = st.st_blksize;
  }

  res = pr_fs_fgetsize(fh->fh_fd, &fs_size);
  if (res < 0 &&
      errno != ENOSYS) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error getting filesystem size for '%s': %s", fh->fh_path,
      strerror(errno));
    fs_size = 0;
  }

  pr_snprintf(mg_size, sizeof(mg_size), "%" PR_LU, (pr_off_t) fs_size);
  format_size_str(mg_size_units, sizeof(mg_size_units), fs_size);

  mg_time = pr_strtime(time(NULL));

  max_clients = get_param_ptr(main_server->conf, "MaxClients", FALSE);

  v = pr_table_get(session.notes, "client-count", NULL);
  if (v != NULL) {
    current_clients = v;
  }

  pr_snprintf(mg_cur, sizeof(mg_cur), "%u",
    current_clients ? *current_clients: 1);

  if (session.conn_class != NULL &&
      session.conn_class->cls_name) {
    const unsigned int *class_clients = NULL;
    config_rec *maxc = NULL;
    unsigned int maxclients = 0;

    v = pr_table_get(session.notes, "class-client-count", NULL);
    if (v != NULL) {
      class_clients = v;
    }

    pr_snprintf(mg_cur_class, sizeof(mg_cur_class), "%u",
      class_clients ? *class_clients : 0);

    /* For the %z variable, first we scan through the MaxClientsPerClass,
     * and use the first applicable one.  If none are found, look for
     * any MaxClients set.
     */

    maxc = find_config(main_server->conf, CONF_PARAM, "MaxClientsPerClass",
      FALSE);
    while (maxc != NULL) {
      pr_signals_handle();

      if (strcmp(maxc->argv[0], session.conn_class->cls_name) != 0) {
        maxc = find_config_next(maxc, maxc->next, CONF_PARAM,
          "MaxClientsPerClass", FALSE);
        continue;
      }

      maxclients = *((unsigned int *) maxc->argv[1]);
      break;
    }

    if (maxclients == 0) {
      maxc = find_config(main_server->conf, CONF_PARAM, "MaxClients", FALSE);
      if (maxc) {
        maxclients = *((unsigned int *) maxc->argv[0]);
      }
    }

    pr_snprintf(mg_class_limit, sizeof(mg_class_limit), "%u", maxclients);

  } else {
    pr_snprintf(mg_class_limit, sizeof(mg_class_limit), "%u",
      max_clients ? *max_clients : 0);
    pr_snprintf(mg_cur_class, sizeof(mg_cur_class), "%u", 0);
  }

  pr_snprintf(mg_max, sizeof(mg_max), "%u", max_clients ? *max_clients : 0);

  user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
  if (user == NULL) {
    user = "";
  }

  rfc1413_ident = pr_table_get(session.notes, "mod_ident.rfc1413-ident", NULL);
  if (rfc1413_ident == NULL) {
    rfc1413_ident = "UNKNOWN";
  }

  memset(buf, '\0', sizeof(buf));
  while (pr_fsio_gets(buf, sizeof(buf), fh) != NULL) {
    char *tmp;

    pr_signals_handle();

    buf[sizeof(buf)-1] = '\0';
    len = strlen(buf);

    while (len > 0 &&
           (buf[len-1] == '\r' || buf[len-1] == '\n')) {
      pr_signals_handle();

      buf[len-1] = '\0';
      len--;
    }

    /* Check for any Variable-type strings. */
    tmp = strstr(buf, "%{");
    while (tmp) {
      char *key, *tmp2;
      const char *val;

      pr_signals_handle();

      tmp2 = strchr(tmp, '}');
      if (tmp2 == NULL) {
        /* No closing '}' found in this string, so no need to look for any
         * another '%{' opening sequence.  Just move on.
         */
        tmp = NULL;
        break;
      }

      key = pstrndup(p, tmp, tmp2 - tmp + 1);

      /* There are a couple of special-case keys to watch for:
       *
       *   env:$var
       *   time:$fmt
       *
       * The Var API does not easily support returning values for keys
       * where part of the value depends on part of the key.  That's why
       * these keys are handled here, instead of in pr_var_get().
       */

      if (strncmp(key, "%{time:", 7) == 0) {
        char time_str[128], *fmt;
        time_t now;
        struct tm *tm;

        fmt = pstrndup(p, key + 7, strlen(key) - 8);

        now = time(NULL);
        memset(time_str, 0, sizeof(time_str));

        tm = pr_localtime(NULL, &now);
        if (tm != NULL) {
          strftime(time_str, sizeof(time_str), fmt, tm);
        }

        val = pstrdup(p, time_str);

      } else if (strncmp(key, "%{env:", 6) == 0) {
        char *env_var;

        env_var = pstrndup(p, key + 6, strlen(key) - 7);
        val = pr_env_get(p, env_var);
        if (val == NULL) {
          pr_trace_msg("var", 4,
            "no value set for environment variable '%s', using \"(none)\"",
            env_var);
          val = "(none)";
        }

      } else {
        val = pr_var_get(key);
        if (val == NULL) {
          pr_trace_msg("var", 4,
            "no value set for name '%s', using \"(none)\"", key);
          val = "(none)";
        }
      }

      outs = sreplace(p, buf, key, val, NULL);
      sstrncpy(buf, outs, sizeof(buf));

      tmp = strstr(outs, "%{");
    }

    outs = sreplace(p, buf,
      "%C", (session.cwd[0] ? session.cwd : "(none)"),
      "%E", main_server->ServerAdmin,
      "%F", mg_size,
      "%f", mg_size_units,
      "%i", "0",
      "%K", "0",
      "%k", "0B",
      "%L", serverfqdn,
      "%M", mg_max,
      "%N", mg_cur,
      "%o", "0",
      "%R", (session.c && session.c->remote_name ?
        session.c->remote_name : "(unknown)"),
      "%T", mg_time,
      "%t", "0",
      "%U", user,
      "%u", rfc1413_ident,
      "%V", main_server->ServerName,
      "%x", session.conn_class ? session.conn_class->cls_name : "(unknown)",
      "%y", mg_cur_class,
      "%z", mg_class_limit,
      NULL);

    /* Always make sure that the lines we send are CRLF-terminated. */
    msg = pstrcat(p, msg, outs, "\r\n", NULL);

    /* Clear the buffer for the next read. */
    memset(buf, '\0', sizeof(buf));
  }

  return msg;
}
