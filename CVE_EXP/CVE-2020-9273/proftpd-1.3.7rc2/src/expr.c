/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2008-2016 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Expression API implementation */

#include "conf.h"

array_header *pr_expr_create(pool *p, unsigned int *argc, char **argv) {
  array_header *acl = NULL;
  unsigned int cnt;
  char *s, *ent;

  if (p == NULL ||
      argc == NULL ||
      argv == NULL ||
      *argv == NULL) {
    errno = EINVAL;
    return NULL;
  }

  cnt = *argc;

  if (cnt > 0) {
    acl = make_array(p, cnt, sizeof(char *));

    /* Skip past the first string in argv, as this is usually the directive. */
    while (cnt-- && *(++argv)) {
      char *sep = ",";

      s = pstrdup(p, *argv);

      if (strstr(s, sep) != NULL) {
        while ((ent = pr_str_get_token(&s, sep)) != NULL) {
          pr_signals_handle();

          if (*ent) {
            *((char **) push_array(acl)) = ent;
          }
        }

      } else {
        *((char **) push_array(acl)) = s;
      }
    }

    *argc = acl->nelts;

  } else {
    acl = make_array(p, 0, sizeof(char *));
    *argc = 0;
  }

  return acl;
}

/* Boolean "class-expression" AND matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
int pr_expr_eval_class_and(char **expr) {
  int found;
  char *class;

  if (expr == NULL ||
      *expr == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (; *expr; expr++) {
    class = *expr;
    found = FALSE;

    if (*class == '!') {
      found = !found;
      class++;
    }

    if (session.conn_class == NULL &&
        !found) {
      return FALSE;
    }

    if (session.conn_class != NULL &&
        strcmp(session.conn_class->cls_name, class) == 0) {
      found = !found;
    }

    if (!found) {
      return FALSE;
    }
  }

  return TRUE;
}

/* Boolean "class-expression" OR matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
int pr_expr_eval_class_or(char **expr) {
  int found;
  char *class;

  if (expr == NULL ||
      *expr == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (; *expr; expr++) {
    class = *expr;
    found = FALSE;

    if (*class == '!') {
      found = !found;
      class++;
    }

    if (session.conn_class == NULL)
      return found;

    if (strcmp(session.conn_class->cls_name, class) == 0)
      found = !found;

    if (found)
      return TRUE;
  }

  return FALSE;
}

/* Boolean "group-expression" AND matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
int pr_expr_eval_group_and(char **expr) {
  int found;
  char *grp;

  if (expr == NULL ||
      *expr == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (; *expr; expr++) {
    grp = *expr;
    found = FALSE;

    if (*grp == '!') {
      found = !found;
      grp++;
    }

    if (session.group &&
        strcmp(session.group, grp) == 0) {
      found = !found;

    } else if (session.groups) {
      register unsigned int i = 0;
      char **elts = session.groups->elts;

      for (i = 0; i < session.groups->nelts; i++) {
        if (elts[i] != NULL &&
            strcmp(elts[i], grp) == 0) {
          found = !found;
          break;
        }
      }
    }

    if (!found)
      return FALSE;
  }

  return TRUE;
}

/* Boolean "group-expression" OR matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
int pr_expr_eval_group_or(char **expr) {
  int found;
  char *grp;

  if (expr == NULL ||
      *expr == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (; *expr; expr++) {
    grp = *expr;
    found = FALSE;

    if (*grp == '!') {
      found = !found;
      grp++;
    }

    if (session.group &&
        strcmp(session.group, grp) == 0) {
      found = !found;

    } else if (session.groups) {
      register unsigned int i = 0;
      char **elts = session.groups->elts;

      for (i = 0; i < session.groups->nelts; i++) {
        if (elts[i] != NULL &&
            strcmp(elts[i], grp) == 0) {
          found = !found;
          break;
        }
      }
    }

    if (found)
      return TRUE;
  }

  return FALSE;
}

/* Boolean "user-expression" AND matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
int pr_expr_eval_user_and(char **expr) {
  int found;
  char *user;

  if (expr == NULL ||
      *expr == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (; *expr; expr++) {
    user = *expr;
    found = FALSE;

    if (*user == '!') {
      found = !found;
      user++;
    }

    if (session.user &&
        strcmp(session.user, user) == 0)
      found = !found;

    if (!found) 
      return FALSE;
  }

  return TRUE;
}

/* Boolean "user-expression" OR matching, returns TRUE if the expression
 * evaluates to TRUE.
 */
int pr_expr_eval_user_or(char **expr) {
  int found;
  char *user;

  if (expr == NULL ||
      *expr == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (; *expr; expr++) {
    user = *expr;
    found = FALSE;

    if (*user == '!') {
      found = !found;
      user++;
    }

    if (session.user &&
        strcmp(session.user, user) == 0)
      found = !found;

    if (found)
      return TRUE;
  }

  return FALSE;
}
