/*
 * ProFTPD: mod_ifversion -- a module supporting conditional configuration
 *                           depending on the proftpd server version
 *
 * Copyright (c) 2009-2015 TJ Saunders
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
 *
 * This is mod_ifversion, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"

#define MOD_IFVERSION_VERSION	"mod_ifversion/0.1"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030602
# error "ProFTPD 1.3.6rc2 or later required"
#endif

/* Support routines
 */

/* These status values are arbitrary; the important part is the values
 * reflect the relationships:
 *
 *  RC < stable < maint
 */
#define IFVERSION_STATUS_RC		100
#define IFVERSION_STATUS_STABLE		300

module ifversion_module;

static int parse_version(char *version_str, unsigned int *version,
    unsigned int *version_status) {
  register unsigned int i;
  char c, *ptr, *tmp;
  int have_suffix = FALSE;
  size_t revision_len = 0;

  /* Parse the given version string.  We expect to see:
   *
   *  major[.minor[.revision[suffix]]]
   *
   * Examples:
   *
   *  "1"
   *  "1.3"
   *  "1.3.3"
   *  "1.3.3rc1"
   *  "1.3.3a"
   */

  /* Quick sanity check */
  if (!PR_ISDIGIT(version_str[0])) {
    return -1;
  }

  /* Parse the major number */
  ptr = strchr(version_str, '.');
  if (ptr) {
    *ptr = '\0';

    tmp = NULL;
    version[0] = (int) strtoul(version_str, &tmp, 10);
    if (tmp && *tmp) {
      *ptr = '.';
      return -1;
    }

    *ptr = '.';

    /* Make sure that there is a character following the period. */
    if (*(ptr + 1) != '\0') {
      version_str = ptr + 1;

    } else {
      return -1;
    }

  } else {
    tmp = NULL;
    version[0] = (int) strtoul(version_str, &tmp, 10);
    if (tmp && *tmp) {
      return -1;
    }

    return 0;
  }

  /* Parse the minor number */
  ptr = strchr(version_str, '.');
  if (ptr) {
    *ptr = '\0';

    tmp = NULL;
    version[1] = (int) strtoul(version_str, &tmp, 10);
    if (tmp && *tmp) {
      *ptr = '.';
      return -1;
    }

    *ptr = '.';

    /* Make sure that there is a character following the period. */
    if (*(ptr + 1) != '\0') {
      version_str = ptr + 1;

    } else {
      return -1;
    }

  } else {
    tmp = NULL;
    version[1] = (int) strtoul(version_str, &tmp, 10);
    if (tmp && *tmp) {
      return -1;
    }

    return 0;
  }

  /* Parse the revision number.  This is trickier, since we have to also
   * account for the suffix, and there is no delimiter between the revision
   * number and the suffix characters.
   *
   * We thus scan every character from here on out.  If they are all digits,
   * then it is a "stable" release (no suffix).  Otherwise, it's either an
   * RC release, a maintenance release, or it's a badly formatted version
   * string.
   */

  for (i = 0; i < strlen(version_str); i++) {
    if (!PR_ISDIGIT(version_str[i])) {
      if (i > 0) {
        have_suffix = TRUE;
        break;
      }

      /* Syntax error */
      return -1;

    } else {
      /* Keep track of the number of characters in the revision number; this
       * is handy for afterwards, assuming we do have a suffix.
       */
      revision_len++;
    }
  }

  if (!have_suffix) {
    tmp = NULL;
    version[2] = (int) strtoul(version_str, &tmp, 10);
    if (tmp && *tmp) {
      return -1;
    }

    /* Stable release */
    *version_status = IFVERSION_STATUS_STABLE;
    return 0;
  }

  ptr = version_str + revision_len;
  c = *ptr;
  *ptr = '\0';

  tmp = NULL;
  version[2] = (int) strtoul(version_str, &tmp, 10);

  if (tmp && *tmp) {
    *ptr = c;
    return -1;
  }

  *ptr = c;

  /* We already know, based on the suffix check, that there are characters
   * after the revision number.
   */
  version_str = ptr;

  /* If the next two characters are "rc" (case-insensitive) followed by
   * digits, it's an RC release.  (If there are no digits, it's a syntax
   * error.)
   *
   * If there only a single character left, it is a maintenance release.
   */

  if (strlen(version_str) == 1) {
    if (!PR_ISALPHA(version_str[0])) {
      /* Syntax error */
      return -1;
    }

    /* Maintenance release. */
    c = toupper(version_str[0]);
    *version_status = IFVERSION_STATUS_STABLE + (c - 'A');
    return 0;
  }

  if (strncasecmp(version_str, "rc", 2) != 0) {
    return -1;
  }

  /* RC release */

  *version_status = IFVERSION_STATUS_RC;

  if (strlen(version_str) == 2) {
    return 0;
  }

  version_str += 2;

  for (i = 0; i < strlen(version_str); i++) {
    if (!PR_ISDIGIT(version_str[i])) {
      /* Syntax error */
      return -1;
    }
  }

  tmp = NULL;
  *version_status += strtoul(version_str, &tmp, 10);

  if (tmp && *tmp) {
    return -1;
  }

  return 0;
}

static int compare_version(pool *p, char *version_str, char **error) {
  char *server_version_str;
  unsigned int version_status = 0, server_version_status = 0;
  unsigned int version[3] = { 0, 0, 0 }, server_version[3] = { 0, 0, 0 };
  int res;

  res = parse_version(version_str, version, &version_status);
  if (res < 0) {
    *error = pstrcat(p, "badly formatted configured version '", version_str,
      "'", NULL);
    return -1;
  }

  server_version_str = pstrdup(p, pr_version_get_str());
  res = parse_version(server_version_str, server_version,
    &server_version_status);
  if (res < 0) {
    *error = pstrcat(p, "badly formatted server version '", server_version_str,
      "'", NULL);
    return -1;
  }

  *error = NULL;

  if (server_version[0] > version[0]) {
    return 1;

  } else if (server_version[0] < version[0]) {
    return -1;

  } else if (server_version[1] > version[1]) {
    return 1;

  } else if (server_version[1] < version[1]) {
    return -1;

  } else if (server_version[2] > version[2]) {
    return 1;

  } else if (server_version[2] < version[2]) {
    return -1;

  } else if (server_version_status > version_status) {
    return 1;

  } else if (server_version_status < version_status) {
    return -1;
  }

  /* Appear to be the same versions. */
  return 0;
}

static int match_version(pool *p, const char *pattern_str, char **error) {
#ifdef PR_USE_REGEX
  pr_regex_t *pre;
  int res;

  pre = pr_regexp_alloc(&ifversion_module);

  res = pr_regexp_compile(pre, pattern_str, REG_EXTENDED|REG_NOSUB|REG_ICASE);
  if (res != 0) {
    char errstr[256];

    memset(errstr, '\0', sizeof(errstr));
    pr_regexp_error(res, pre, errstr, sizeof(errstr)-1);

    pr_regexp_free(NULL, pre);
    *error = pstrcat(p, "unable to compile pattern '", pattern_str, "': ",
      errstr, NULL);

    return 0;
  }

  res = pr_regexp_exec(pre, pr_version_get_str(), 0, NULL, 0, 0, 0);
  if (res != 0) {
    *error = pstrcat(p, "server version '", pr_version_get_str(),
      "' failed to match pattern '", pattern_str, "'", NULL);
  }

  pr_regexp_free(NULL, pre);
  return (res == 0 ? 1 : 0);

#else
  *error = pstrdup(p, "system does not support POSIX regular expressions");
  return 0;
#endif /* regex support */
}

/* Configuration handlers
 */

/* Usage: <IfVersion [!]op version-string|regex> */
MODRET start_ifversion(cmd_rec *cmd) {
  unsigned int ifversion_ctx_count = 1;
  int compared, matched = FALSE, negated = FALSE;
  char buf[PR_TUNABLE_BUFFER_SIZE], *config_line = NULL;
  char *error = NULL, *version_str = NULL, *op_str = NULL;
  size_t op_len;

  if (cmd->argc-1 == 0 ||
      cmd->argc-1 > 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  if (cmd->argc-1 == 2) {
    op_str = cmd->argv[1];

    if (*op_str == '!' &&
        strlen(op_str) > 1) {
      negated = TRUE;
      op_str++;
    }

    op_len = strlen(op_str);
    version_str = cmd->argv[2];

  } else {
    /* Assume that if only a version-string was supplied, the operator
     * is intended to be the equality operator.
     */
    op_str = "=";
    op_len = 1;
    version_str = cmd->argv[1];
  }

  switch (*op_str) {
    case '=':
      if (*version_str != '/') {
        /* Normal equality comparison */
        compared = compare_version(cmd->tmp_pool, version_str, &error);
        if (error != NULL) {
          CONF_ERROR(cmd, error);
        }

        matched = (compared == 0);
        break;
      }

      /* Otherwise, it's a regular expression */
      if (version_str[strlen(version_str)-1] != '/') {
        CONF_ERROR(cmd, "Missing terminating '/' of regular expression");
      }

      /* Fall through to the next case in order to handle/evaluate the
       * regular expression.  Be sure to remove the bracketing '/' characters
       * for the regex compilation.
       */
      version_str[strlen(version_str)-1] = '\0';
      version_str++;

    case '~': 
      /* Regular expression */
      matched = match_version(cmd->tmp_pool, version_str, &error);
      if (error != NULL) {
        CONF_ERROR(cmd, error);
      }

      break;

    case '<':
      compared = compare_version(cmd->tmp_pool, version_str, &error);
      if (error != NULL) {
        CONF_ERROR(cmd, error);
      }

      if (compared == -1 ||
          (op_len == 2 && compared == 0)) {
        matched = TRUE;
      }

      break;

    case '>':
      compared = compare_version(cmd->tmp_pool, version_str, &error);
      if (error != NULL) {
        CONF_ERROR(cmd, error);
      }

      if (compared == 1 ||
          (op_len == 2 && compared == 0)) {
        matched = TRUE;
      }

      break;

    default:
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown comparison operator '",
        op_str, "'", NULL));
  } 

  if ((matched && !negated) ||
      (!matched && negated)) {
    pr_log_debug(DEBUG3, "%s: using '%s %s' section at line %u",
      (char *) cmd->argv[0], (char *) cmd->argv[1], (char *) cmd->argv[2],
      pr_parser_get_lineno()); return PR_HANDLED(cmd);
  }

  pr_log_debug(DEBUG3, "%s: skipping '%s %s' section at line %u",
    (char *) cmd->argv[0], (char *) cmd->argv[1], (char *) cmd->argv[2],
    pr_parser_get_lineno());

  while (ifversion_ctx_count > 0 &&
         (config_line = pr_parser_read_line(buf, sizeof(buf))) != NULL) {
    pr_signals_handle();

    if (strncasecmp(config_line, "<IfVersion", 10) == 0) {
      ifversion_ctx_count++;
    }

    if (strcasecmp(config_line, "</IfVersion>") == 0) {
      ifversion_ctx_count--;
    }
  }

  /* If there are still unclosed <IfVersion> sections, signal an error.
   */
  if (ifversion_ctx_count > 0) {
    CONF_ERROR(cmd, "unclosed <IfVersion> section");
  }

  return PR_HANDLED(cmd);
}

MODRET end_ifversion(cmd_rec *cmd) {
  return PR_HANDLED(cmd);
}

/* Module API tables
 */

static conftable ifversion_conftab[] = {
  { "<IfVersion>",	start_ifversion,	NULL },
  { "</IfVersion>",	end_ifversion,		NULL },
  { NULL }
};

module ifversion_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "ifversion",

  /* Module configuration handler table */
  ifversion_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  NULL,

  /* Session initialization function */
  NULL,

  /* Module version */
  MOD_IFVERSION_VERSION
};
