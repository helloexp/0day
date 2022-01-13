/*
 * ProFTPD: mod_lang -- a module for handling the LANG command [RFC2640]
 * Copyright (c) 2006-2017 The ProFTPD Project
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

#include "conf.h"

#define MOD_LANG_VERSION		"mod_lang/1.1"

#if PROFTPD_VERSION_NUMBER < 0x0001030101
# error "ProFTPD 1.3.1rc1 or later required"
#endif

#if PR_USE_NLS

#ifdef HAVE_LANGINFO_H
# include <langinfo.h>
#endif

extern xaset_t *server_list;

module lang_module;

#define LANG_DEFAULT_LANG	"en_US"

static const char *lang_curr = LANG_DEFAULT_LANG;
static const char *lang_default = LANG_DEFAULT_LANG;
static int lang_engine = TRUE;
static pool *lang_pool = NULL;
static array_header *lang_list = NULL;
static pr_table_t *lang_aliases = NULL;
static const char *lang_path = PR_LOCALE_DIR;

static unsigned long lang_opts = 0UL;
#define LANG_OPT_PREFER_SERVER_ENCODING		0x0001
#define LANG_OPT_REQUIRE_VALID_ENCODING		0x0002

static int lang_use_encoding = -1;
static const char *lang_local_charset = NULL, *lang_client_charset = NULL;

/* Support routines
 */

static void lang_feat_add(pool *p) {
  char *feat_str = "";

  if (lang_list &&
      lang_list->nelts > 0) {
    register unsigned int i;
    char **langs;
    size_t feat_strlen = 0;
 
    langs = lang_list->elts;
    for (i = 0; i < lang_list->nelts; i++) {
      char *lang_dup, *tmp;

      /* Convert all locales in the list to RFC1766 form, i.e. hyphens instead
       * of underscores.
       */
      lang_dup = pstrdup(p, langs[i]);
      tmp = strchr(lang_dup, '_');
      if (tmp) {
        *tmp = '-';
      }

      feat_str = pstrcat(p, feat_str, lang_dup, NULL);
      if (strcasecmp(lang_curr, lang_dup) == 0 ||
          strcasecmp(lang_curr, langs[i]) == 0) {
        /* This is the currently selected language; mark it with an asterisk,
         * as per RFC2640, Section 4.3.
         */
        feat_str = pstrcat(p, feat_str, "*", NULL);
      }

      feat_str = pstrcat(p, feat_str, ";", NULL);
    }
 
    feat_strlen = strlen(feat_str);

    /* Trim the trailing semicolon. */
    if (feat_str[feat_strlen-1] == ';') {
      feat_str[feat_strlen-1] = '\0';
    }

    feat_str = pstrcat(p, "LANG ", feat_str, NULL);
    pr_feat_add(feat_str);

  } else {
    feat_str = pstrcat(p, "LANG ", lang_curr, NULL);
    pr_feat_add(feat_str);
  }
}

static void lang_feat_remove(void) {
  const char *feat, *lang_feat = NULL;

  feat = pr_feat_get();
  while (feat) {
    pr_signals_handle();

    if (strncmp(feat, C_LANG, 4) == 0) {
      lang_feat = feat;
      break;
    }

    feat = pr_feat_get_next();
  }

  if (lang_feat)
    pr_feat_remove(lang_feat);
}

static const char *lang_bind_domain(void) {
  const char *res = NULL;

#ifdef HAVE_LIBINTL_H
  pr_log_debug(DEBUG9, MOD_LANG_VERSION
    ": binding to text domain 'proftpd' using locale path '%s'", lang_path);
  res = bindtextdomain("proftpd", lang_path); 
  if (res == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
      ": unable to bind to text domain 'proftpd' using locale path '%s': %s",
      lang_path, strerror(errno));
    return NULL;

  } else {
    textdomain("proftpd");
    pr_log_debug(DEBUG9, MOD_LANG_VERSION ": using locale files in '%s'", res);
  }

#else
  pr_log_debug(DEBUG7, MOD_LANG_VERSION
    ": unable to bind to text domain 'proftpd', lacking libintl support");
  errno = ENOSYS;
#endif /* !HAVE_LIBINTL_H */

  return res;
}

static int lang_set_lang(pool *p, const char *lang) {
  char *curr_lang;

  if (lang_aliases != NULL) {
    const void *v;

    /* Check to see if the given lang has an alias that has been determined
     * to be acceptable.
     */

    v = pr_table_get(lang_aliases, lang, NULL);
    if (v != NULL) {
      pr_log_debug(DEBUG9, MOD_LANG_VERSION ": '%s' is an alias for '%s'",
        lang, (const char *) v);
      lang = v;
    }
  }

  curr_lang = pstrdup(p, setlocale(LC_MESSAGES, NULL));

  /* XXX Do we need to set LC_COLLATE (e.g. for sorted directory listings)
   * and/or LC_CTYPE (for iconv conversion) here as well?
   */

  if (setlocale(LC_MESSAGES, lang) == NULL) {
    if (errno == ENOENT) {
      pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
        ": unknown/unsupported language '%s', ignoring", lang);

    } else {
      pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
        ": unable to set LC_MESSAGES to '%s': %s", lang, strerror(errno));
      return -1;
    }

  } else {
    curr_lang = setlocale(LC_MESSAGES, NULL);
    pr_log_debug(DEBUG4, MOD_LANG_VERSION ": using %s messages",
      *lang ? lang : curr_lang);


    /* Set LC_COLLATE for strcoll(3), for sorted directory listings. */
    if (setlocale(LC_COLLATE, curr_lang) == NULL) {
      pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
        ": unable to set LC_COLLATE to '%s': %s", curr_lang, strerror(errno));
    }

    /* Set LC_CTYPE for conversion, case-sensitive comparisons, and regexes. */
    if (setlocale(LC_CTYPE, curr_lang) == NULL) {
      pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
        ": unable to set LC_CTYPE to '%s': %s", curr_lang, strerror(errno));
    }

    /* Set LC_MONETARY, for handling e.g the Euro symbol. */
    if (setlocale(LC_MONETARY, curr_lang) == NULL) {
      pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
        ": unable to set LC_MONETARY to '%s': %s", curr_lang, strerror(errno));
    }
  }

  /* In order to make gettext lookups work properly on some platforms
   * (i.e. FreeBSD), the LANG environment variable MUST be set.  Apparently
   * on these platforms, bindtextdomain(3) is not enough.  Sigh.
   *
   * This post first tipped me off to the solution for this problem:
   *
   *  http://fixunix.com/unix/243882-freebsd-locales.html
   */

  pr_env_unset(session.pool, "LANG");
  pr_env_set(session.pool, "LANG", lang);

  return 0;
}

/* Supports comparison of RFC1766 language tags (case-insensitive, using
 * hyphens) from the client with the underscore-using locale names usually
 * used by iconv and setlocale().
 */
static int lang_supported(pool *p, const char *lang) {
  register unsigned int i;
  size_t lang_len;
  char *lang_dup, **langs;
  int ok = FALSE;

  if (lang_list == NULL) {
    errno = EPERM;
    return -1;
  }

  if (lang_aliases != NULL) {
    const void *v;
    
    /* Check to see if the given lang has an alias that has been determined
     * to be acceptable.
     */

    v = pr_table_get(lang_aliases, lang, NULL);
    if (v != NULL) {
      pr_log_debug(DEBUG9, MOD_LANG_VERSION ": using '%s' as alias for '%s'",
        (const char *) v, lang);
      lang = v;
    }
  }

  lang_dup = pstrdup(p, lang);

  lang_len = strlen(lang_dup);
  if (lang_len > 4) {

    /* Transform something like "en-US" into "en_US". */
    if (lang_dup[2] == '-') {
      lang_dup[2] = '_';
    }
  }

  langs = lang_list->elts;

  for (i = 0; i < lang_list->nelts; i++) {
    if (strcasecmp(langs[i], lang_dup) == 0) {
      ok = TRUE;
      break;
    }
  }

  if (!ok) {
    errno = ENOENT;
    return -1;
  }

  return 0;
}

/* Lookup/handle any UseEncoding configuration. */
static int process_encoding_config(int *utf8_client_encoding) {
  config_rec *c;
  int strict_encoding;

  c = find_config(main_server->conf, CONF_PARAM, "UseEncoding", FALSE);
  if (c == NULL) {
    errno = ENOENT;
    return -1;
  }

  if (c->argc == 1) {
    lang_use_encoding = *((int *) c->argv[0]);
    if (lang_use_encoding == TRUE) {
      pr_fs_use_encoding(TRUE);

    } else {
      pr_encode_disable_encoding();
      pr_fs_use_encoding(FALSE);
    }

    return 0;
  }

  lang_local_charset = c->argv[0];
  lang_client_charset = c->argv[1];
  strict_encoding = *((int *) c->argv[2]);

  if (strict_encoding == TRUE) {
    /* Fold the UseEncoding "strict" keyword functionality into LangOptions;
     * we want to move people that way anyway.
     */
    lang_opts |= LANG_OPT_PREFER_SERVER_ENCODING;
  }

  if (strcasecmp(lang_client_charset, "UTF8") == 0 ||
      strcasecmp(lang_client_charset, "UTF-8") == 0) {
    if (utf8_client_encoding) {
      *utf8_client_encoding = TRUE;
    }
  }

  if (pr_encode_set_charset_encoding(lang_local_charset,
      lang_client_charset) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
      ": error setting local charset '%s', client charset '%s': %s",
      lang_local_charset, lang_client_charset, strerror(errno));
    pr_fs_use_encoding(FALSE);

  } else {
    pr_log_debug(DEBUG3, MOD_LANG_VERSION ": using local charset '%s', "
      "client charset '%s' for path encoding", lang_local_charset,
      lang_client_charset);
    pr_fs_use_encoding(TRUE);

    /* Make sure that gettext() uses the specified charset as well. */
    if (bind_textdomain_codeset("proftpd", lang_client_charset) == NULL) {
      pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
        ": error setting client charset '%s' for localised messages: %s",
        lang_client_charset, strerror(errno));
    }
  }

  return 0;
}

/* Configuration handlers
 */

/* usage: LangDefault lang */
MODRET set_langdefault(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: LangEngine on|off */
MODRET set_langengine(cmd_rec *cmd) {
  int b;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  b = get_boolean(cmd, 1);
  if (b == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = b;

  return PR_HANDLED(cmd);
}

/* usage: LangOptions opt1 opt2 ... */
MODRET set_langoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i = 0;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0)
    CONF_ERROR(cmd, "wrong number of parameters");

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "PreferServerEncoding") == 0) {
      opts |= LANG_OPT_PREFER_SERVER_ENCODING;

    } else if (strcmp(cmd->argv[i], "RequireValidEncoding") == 0) {
      opts |= LANG_OPT_REQUIRE_VALID_ENCODING;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown LangOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: LangPath path */
MODRET set_langpath(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use path '",
      cmd->argv[1], "' for locale files", NULL));
  }

  lang_path = pstrdup(permanent_pool, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: UseEncoding on|off|local-charset client-charset ["strict"]*/
MODRET set_useencoding(cmd_rec *cmd) {
  config_rec *c;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc == 2) {
    int use_encoding = -1;

    use_encoding = get_boolean(cmd, 1);
    if (use_encoding == -1) {
      CONF_ERROR(cmd, "expected Boolean parameter");
    }

    c = add_config_param(cmd->argv[0], 1, NULL);
    c->argv[0] = pcalloc(c->pool, sizeof(int));
    *((int *) c->argv[0]) = use_encoding;

  } else if (cmd->argc == 3 ||
             cmd->argc == 4) {

    if (cmd->argc == 4) {
      if (strcasecmp(cmd->argv[3], "strict") != 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown UseEncoding keyword '",
          cmd->argv[3], "'", NULL));
      }
    }

    c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);
    c->argv[0] = pstrdup(c->pool, cmd->argv[1]);
    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);
    c->argv[2] = palloc(c->pool, sizeof(int));

    if (cmd->argc == 4) {
      /* UseEncoding strict keyword in effect. */
      *((int *) c->argv[2]) = TRUE;

    } else {
      /* UseEncoding strict keyword NOT in effect. */
      *((int *) c->argv[2]) = FALSE;
    }

  } else {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET lang_lang(cmd_rec *cmd) {
  unsigned char *authenticated;

  if (!lang_engine)
    return PR_DECLINED(cmd);

  if (!dir_check(cmd->tmp_pool, cmd, cmd->group, session.cwd, NULL)) {
    pr_log_debug(DEBUG4, MOD_LANG_VERSION ": LANG command denied by <Limit>");
    pr_response_add_err(R_500, _("Unable to handle command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  /* If the user has already authenticated (and thus possibly chrooted),
   * deny the command.  Once chrooted, we will not have access to the
   * message catalog files anymore.
   *
   * True, the user may not have been chrooted, but if we allow non-chrooted
   * users to issue LANG commands while chrooted users cannot, it can
   * constitute an information leak.  Best to avoid that altogether.
   */
  authenticated = get_param_ptr(cmd->server->conf, "authenticated", FALSE);
  if (authenticated &&
      *authenticated == TRUE) {
    pr_log_debug(DEBUG7, MOD_LANG_VERSION ": assuming language files are "
      "unavailable after login, denying LANG command");
    pr_response_add_err(R_500, _("Unable to handle command"));

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  if (cmd->argc > 2) {
    pr_response_add_err(R_501, _("Invalid number of parameters"));

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  if (cmd->argc == 1) {
    pr_log_debug(DEBUG7, MOD_LANG_VERSION
      ": resetting to default language '%s'", lang_default);

    if (lang_set_lang(cmd->tmp_pool, lang_default) < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
        ": unable to use LangDefault '%s': %s", lang_default, strerror(errno));
      pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
        ": using LC_ALL environment variable value instead");
    }

    pr_response_add(R_200, _("Using default language %s"), lang_default);
    return PR_HANDLED(cmd);
  }

  if (lang_supported(cmd->tmp_pool, cmd->argv[1]) < 0) {
    pr_log_debug(DEBUG3, MOD_LANG_VERSION ": language '%s' unsupported: %s",
      (char *) cmd->argv[1], strerror(errno));
    pr_response_add_err(R_504, _("Language %s not supported"),
      (char *) cmd->argv[1]);

    pr_cmd_set_errno(cmd, EPERM);
    errno = EPERM;
    return PR_ERROR(cmd);
  }

  pr_log_debug(DEBUG7, MOD_LANG_VERSION
    ": setting to client-requested language '%s'", (char *) cmd->argv[1]);

  if (lang_set_lang(cmd->tmp_pool, cmd->argv[1]) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
      ": unable to use client-requested language '%s': %s",
      (char *) cmd->argv[1], strerror(errno));
    pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
      ": using LangDefault '%s' instead", lang_default);

    if (lang_set_lang(cmd->tmp_pool, lang_default) < 0) {
      pr_log_pri(PR_LOG_WARNING, MOD_LANG_VERSION
        ": unable to use LangDefault '%s': %s", lang_default, strerror(errno));
      pr_session_disconnect(&lang_module, PR_SESS_DISCONNECT_BAD_CONFIG, NULL);
    }
  }

  lang_curr = pstrdup(lang_pool, cmd->argv[1]);

  pr_log_debug(DEBUG5, MOD_LANG_VERSION
    ": now using client-requested language '%s'", lang_curr);

  /* If successful, remove the previous FEAT line for LANG, and update it
   * with a new one showing the currently selected language.
   */

  lang_feat_remove();
  lang_feat_add(cmd->tmp_pool);

  pr_response_add(R_200, _("Using language %s"), lang_curr);
  return PR_HANDLED(cmd);
}

MODRET lang_post_pass(cmd_rec *cmd) {
  (void) process_encoding_config(NULL);
  return PR_DECLINED(cmd);
}

MODRET lang_utf8(cmd_rec *cmd) {
  register unsigned int i;
  int use_utf8;
  const char *curr_encoding;
  char *method;

  method = pstrdup(cmd->tmp_pool, cmd->argv[0]);

  /* Convert underscores to spaces in the method name, for prettier
   * logging.
   */
  for (i = 0; method[i]; i++) {
    if (method[i] == '_') {
      method[i] = ' ';
    }
  }

  if (cmd->argc != 2) {
    pr_response_add_err(R_501, _("'%s' not understood"), method);

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  use_utf8 = get_boolean(cmd, 1);
  if (use_utf8 < 0) {
    pr_response_add_err(R_501, _("'%s' not understood"), method);

    pr_cmd_set_errno(cmd, EINVAL);
    errno = EINVAL;
    return PR_ERROR(cmd);
  }

  curr_encoding = pr_encode_get_encoding();
  if (curr_encoding != NULL) {
    pr_log_debug(DEBUG9, MOD_LANG_VERSION
      ": Handling OPTS UTF8 %s (current encoding is '%s')",
      (char *) cmd->argv[1], curr_encoding);

  } else {
    pr_log_debug(DEBUG9, MOD_LANG_VERSION
      ": Handling OPTS UTF8 %s (encoding currently disabled)",
      (char *) cmd->argv[1]);
  }

  if (pr_encode_is_utf8(curr_encoding) == TRUE) {
    if (use_utf8) {
      /* Client requested that we use UTF8, and we already are.  Nothing
       * more needs to be done.
       */
      pr_response_add(R_200, _("UTF8 set to on"));

    } else {
      /* Client requested that we NOT use UTF8 (i.e. "OPTS UTF8 off"), and
       * we are.  Need to disable encoding, then, unless the
       * LangOptions/UseEncoding settings dictate that we MUST use UTF8.
       */

      if (lang_use_encoding == TRUE) {
        /* We have explicit instructions; we cannot change the encoding use as
         * requested by the client.
         */
        pr_log_debug(DEBUG5, MOD_LANG_VERSION
          ": unable to accept 'OPTS UTF8 off' due to LangOptions/UseEncoding "
          "directive in config file");
        pr_response_add_err(R_451, _("Unable to accept %s"), method);

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);

      } else if (lang_local_charset != NULL &&
                 lang_client_charset != NULL) {

        /* UseEncoding configured with specific charsets, and the client
         * requested that we turn UTF8 support off.  Easy enough; just
         * (re)set the encoding to use the configured charsets.
         */

        if (lang_opts & LANG_OPT_PREFER_SERVER_ENCODING) {
          /* We have explicit instructions; we cannot change the encoding
           * use as requested by the client.
           */
          pr_log_debug(DEBUG5, MOD_LANG_VERSION
            ": unable to accept 'OPTS UTF8 off' due to "
            "LangOptions/UseEncoding directive in config file");
          pr_response_add_err(R_451, _("Unable to accept %s"), method);

          pr_cmd_set_errno(cmd, EPERM);
          errno = EPERM;
          return PR_ERROR(cmd);
        }

        if (pr_encode_set_charset_encoding(lang_local_charset,
            lang_client_charset) < 0) {

          pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
            ": error setting local charset '%s', client charset '%s': %s",
            lang_local_charset, lang_client_charset, strerror(errno));
          pr_fs_use_encoding(FALSE);
          pr_response_add_err(R_451, _("Unable to accept %s"), method);

          pr_cmd_set_errno(cmd, EPERM);
          errno = EPERM;
          return PR_ERROR(cmd);
        }

        pr_log_debug(DEBUG3, MOD_LANG_VERSION ": using local charset '%s', "
          "client charset '%s' for path encoding", lang_local_charset,
          lang_client_charset);
        pr_fs_use_encoding(TRUE);
        pr_response_add(R_200, _("UTF8 set to off"));
        return PR_HANDLED(cmd);
      }

      pr_log_debug(DEBUG5, MOD_LANG_VERSION
        ": disabling use of UTF8 encoding as per client's request");

      /* No explicit UseEncoding instructions; we can turn off encoding. */
      pr_encode_disable_encoding();
      pr_fs_use_encoding(FALSE);
      pr_response_add(R_200, _("UTF8 set to off"));
    }

  } else {
    if (use_utf8) {
      /* Client requested that we use UTF8 (i.e. "OPTS UTF8 on"), and we
       * currently are not.  Enable UTF8 encoding, unless the
       * LangOptions/UseEncoding setting dictates that we cannot.
       */

      if (lang_use_encoding == FALSE) {
        /* We have explicit instructions. */
        pr_log_debug(DEBUG5, MOD_LANG_VERSION
          ": unable to accept 'OPTS UTF8 on' due to LangOptions/UseEncoding "
          "directive in config file");
        pr_response_add_err(R_451, _("Unable to accept %s"), method);

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);

      } else if (lang_opts & LANG_OPT_PREFER_SERVER_ENCODING) {
        /* We have explicit instructions; we cannot change the encoding use
         * as requested by the client.
         */
        pr_log_debug(DEBUG5, MOD_LANG_VERSION
          ": unable to accept 'OPTS UTF8 on' due to LangOptions/UseEncoding "
          "directive in config file");
        pr_response_add_err(R_451, _("Unable to accept %s"), method);

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      } 

      pr_log_debug(DEBUG5, MOD_LANG_VERSION
        ": enabling use of UTF8 encoding as per client's request");

      /* No explicit UseEncoding instructions; we can turn on encoding. */
      if (pr_encode_enable_encoding("UTF-8") < 0) {
        pr_log_debug(DEBUG3, MOD_LANG_VERSION
          ": error enabling UTF8 encoding: %s", strerror(errno));
        pr_response_add_err(R_451, _("Unable to accept %s"), method);

        pr_cmd_set_errno(cmd, EPERM);
        errno = EPERM;
        return PR_ERROR(cmd);
      }

      pr_fs_use_encoding(TRUE);
      pr_response_add(R_200, _("UTF8 set to on"));

    } else {
      /* Client requested that we not use UTF8, and we are not.  Nothing more
       * needs to be done.
       */
      pr_response_add(R_200, _("UTF8 set to off"));
    }
  }

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

static void lang_postparse_ev(const void *event_data, void *user_data) {
  pool *tmp_pool;
  config_rec *c;
  DIR *dirh;
  server_rec *s;
  const char *locale_path = NULL;

  c = find_config(main_server->conf, CONF_PARAM, "LangEngine", FALSE);
  if (c) {
    int engine;

    engine = *((int *) c->argv[0]);
    if (!engine)
      return;
  }

  /* Scan the LangPath for the .mo files to read in. */

  locale_path = lang_bind_domain();
  if (locale_path == NULL)
    return;

  /* Scan locale_path using readdir(), to get the list of available
   * translations/langs.  Make sure to check for presence of 'proftpd.mo'
   * in the directories:
   *
   *  $lang/LC_MESSAGES/proftpd.mo
   *
   * In addition, make sure the directory name is a locale acceptable to
   * setlocale(3).
   */

  tmp_pool = make_sub_pool(lang_pool);

  dirh = opendir(locale_path);
  if (dirh != NULL) {
    register unsigned int i;
    struct dirent *dent;
    char *curr_locale, *langs_str = "", **langs = NULL;

    if (!lang_list) {
      lang_list = make_array(lang_pool, 3, sizeof(char *));
    }

    curr_locale = pstrdup(tmp_pool, setlocale(LC_MESSAGES, NULL));

    while ((dent = readdir(dirh)) != NULL) {
      char *mo;
      struct stat st;

      pr_signals_handle();

      if (strncmp(dent->d_name, ".", 2) == 0 ||
          strncmp(dent->d_name, "..", 3) == 0) {
        continue;
      }

      mo = pdircat(tmp_pool, locale_path, dent->d_name, "LC_MESSAGES",
        "proftpd.mo", NULL);

      if (stat(mo, &st) == 0) {
        register unsigned int j;
        char *locale_name;

        /* Check that dent->d_name is a valid language name according to
         * setlocale(3) before adding it to the list.
         *
         * Note that proftpd's .po files do not include the optional codeset
         * modifier in the file name, i.e.:
         *
         *  lang[_territory[.codeset[@modifier]]]
         *
         * Thus if setlocale() returns ENOENT, we will automatically try
         * appending a ".UTF-8" to see if setlocale() accepts that.
         */

        locale_name = dent->d_name;

        for (j = 0; j < 2; j++) {
          if (setlocale(LC_MESSAGES, locale_name) != NULL) {
            *((char **) push_array(lang_list)) = pstrdup(lang_pool,
              locale_name);

            /* If this is not the first setlocale() attempt, then we have
             * automatically appending ".UTF-8" (or ".utf8") to the file name.
             * In which case we want to allow the non-".UTF-8"/non-".utf8"
             * locale name as an acceptable alias.
             */
            if (j > 0) {
              if (lang_aliases == NULL) {
                lang_aliases = pr_table_alloc(lang_pool, 0);
              }

              pr_table_add(lang_aliases, pstrdup(lang_pool, dent->d_name),
                pstrdup(lang_pool, locale_name), 0);

              /* Make sure the original name up in our "supported languages"
               * list as well.
               */
              *((char **) push_array(lang_list)) = pstrdup(lang_pool,
                dent->d_name);
            }

            break;
          }

          if (errno == ENOENT) {
            if (j == 0) {
              locale_name = pstrcat(tmp_pool, dent->d_name, ".UTF-8", NULL);
              continue;

            } else {
              pr_log_debug(DEBUG5, MOD_LANG_VERSION
                ": skipping possible language '%s': not supported by "
                "setlocale(3); see `locale -a'", dent->d_name);
            }

          } else {
            pr_log_debug(DEBUG5, MOD_LANG_VERSION
              ": skipping possible language '%s': %s", dent->d_name,
              strerror(errno));
          }
        }
      }
    }

    /* Restore the current locale. */
    setlocale(LC_MESSAGES, curr_locale);

    closedir(dirh);

    langs = lang_list->elts;
    for (i = 0; i < lang_list->nelts; i++) {
      langs_str = pstrcat(tmp_pool, langs_str, *langs_str ? ", " : "",
        langs[i], NULL);
    }

    if (lang_list->nelts > 0) {
      pr_log_debug(DEBUG8, MOD_LANG_VERSION
      ": added the following supported languages: %s", langs_str);
    }

  } else {
    pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
      ": unable to scan the localised files in '%s': %s", locale_path,
      strerror(errno));
  }

  /* Iterate through the server list, checking each for a configured
   * LangDefault.  If configured, make sure that the specified language is
   * supported.
   */

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    c = find_config(s->conf, CONF_PARAM, "LangDefault", FALSE);
    if (c) {
      char *lang = c->argv[0];

      if (lang_supported(tmp_pool, lang) < 0) {
        pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
          ": LangDefault '%s', configured for server '%s', is not a supported "
          "language, removing", lang, s->ServerName);
        pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
          ": Perhaps proftpd has not yet been translated into '%s'", lang);
        remove_config(s->conf, "LangDefault", FALSE);
      }
    }
  }

  if (tmp_pool)
    destroy_pool(tmp_pool);
}

static void lang_restart_ev(const void *event_data, void *user_data) {
  destroy_pool(lang_pool);
  lang_curr = LANG_DEFAULT_LANG;
  lang_list = NULL;
  lang_aliases = NULL;

  lang_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(lang_pool, MOD_LANG_VERSION);
}

/* Initialization functions
 */

static int lang_init(void) {
  lang_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(lang_pool, MOD_LANG_VERSION);

  pr_event_register(&lang_module, "core.postparse", lang_postparse_ev, NULL);
  pr_event_register(&lang_module, "core.restart", lang_restart_ev, NULL);

  return 0;
}

static int lang_sess_init(void) {
  config_rec *c;
  int res, utf8_client_encoding = FALSE;

  c = find_config(main_server->conf, CONF_PARAM, "LangEngine", FALSE);
  if (c != NULL) {
    lang_engine = *((int *) c->argv[0]);
  }

  if (lang_engine == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "LangDefault", FALSE);
  if (c != NULL) {
    char *lang;

    lang = c->argv[0];

    if (lang_set_lang(lang_pool, lang) < 0) {
      pr_log_pri(PR_LOG_NOTICE, MOD_LANG_VERSION
        ": unable to use LangDefault '%s': %s", lang, strerror(errno));
    }

    pr_log_debug(DEBUG9, MOD_LANG_VERSION ": using LangDefault '%s'", lang);
    lang_curr = lang_default = lang;

  } else {
    /* No explicit default language configured; rely on the environment
     * variables (which will already have been picked up).
     */

    lang_curr = pstrdup(lang_pool, setlocale(LC_MESSAGES, NULL));
    if (strcasecmp(lang_curr, "C") == 0) {
      lang_curr = LANG_DEFAULT_LANG;
    }

    lang_default = lang_curr;

    /* If a list of languages is empty (perhaps because the message catalogs
     * could not be found for some reason), we should still have an entry for
     * the current language.
     */
    if (lang_list == NULL) {
      lang_list = make_array(lang_pool, 1, sizeof(char *));
    }

    if (lang_list->nelts == 0) {
      *((char **) push_array(lang_list)) = pstrdup(lang_pool, lang_curr);
    } 
  }

  c = find_config(main_server->conf, CONF_PARAM, "LangOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    lang_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "LangOptions", FALSE);
  }

  if (lang_opts & LANG_OPT_REQUIRE_VALID_ENCODING) {
    unsigned long encoding_policy;

    encoding_policy = pr_encode_get_policy();
    encoding_policy |= PR_ENCODE_POLICY_FL_REQUIRE_VALID_ENCODING;

    pr_encode_set_policy(encoding_policy);
  }

  res = process_encoding_config(&utf8_client_encoding);
  if (res < 0 &&
      errno == ENOENT) {
    /* Default is to use UTF8. */
    pr_fs_use_encoding(TRUE);
  }

  /* If the PreferServerEncoding LangOption is not set, OR if the encoding
   * configured explicitly requests UTF8 from the client, then we can list
   * UTF8 in the FEAT response. 
   */
  if (!(lang_opts & LANG_OPT_PREFER_SERVER_ENCODING) ||
      utf8_client_encoding == TRUE) {
    pr_feat_add("UTF8");
  }

  /* Configure a proper FEAT line, for our supported languages and our
   * default language.
   */
  lang_feat_add(main_server->pool);

  return 0;
}

/* Module API tables
 */

static conftable lang_conftab[] = {
  { "LangDefault",	set_langdefault,	NULL },
  { "LangEngine",	set_langengine,		NULL },
  { "LangOptions",	set_langoptions,	NULL },
  { "LangPath",		set_langpath,		NULL },
  { "UseEncoding",	set_useencoding,	NULL },
  { NULL }
};

static cmdtable lang_cmdtab[] = {
  { CMD,	C_LANG,			G_NONE,	lang_lang,	FALSE,	FALSE },
  { CMD,	C_OPTS "_UTF8",		G_NONE,	lang_utf8,	FALSE,	FALSE },
  { POST_CMD,	C_PASS,			G_NONE,	lang_post_pass,	FALSE,	FALSE },
  { 0, NULL }
};

module lang_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "lang",

  /* Module configuration handler table */
  lang_conftab,

  /* Module command handler table */
  lang_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  lang_init,

  /* Session initialization function */
  lang_sess_init,

  /* Module version */
  MOD_LANG_VERSION
};

#endif /* PR_USE_NLS */
