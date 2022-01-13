/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2004-2016 The ProFTPD Project team
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

/* Variables API implementation */

#include "conf.h"

struct var {
  int v_type;
  const char *v_desc;
  void *v_val;
  void *v_data;
  size_t v_datasz;
};

static pool *var_pool = NULL;
static pr_table_t *var_tab = NULL;

typedef const char *(*var_vstr_cb)(void *, size_t);

static const char *trace_channel = "var";

/* Public API
 */

int pr_var_delete(const char *name) {
  if (var_tab == NULL) {
    errno = EPERM;
    return -1;
  }

  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }

  return pr_table_remove(var_tab, name, NULL) ? 0 : -1;
}

int pr_var_exists(const char *name) {
  if (var_tab == NULL) {
    errno = EPERM;
    return -1;
  }

  if (name == NULL) {
    errno = EINVAL;
    return -1;
  }

  return pr_table_exists(var_tab, name) > 0 ? TRUE : FALSE;
}

const char *pr_var_get(const char *name) {
  const struct var *v = NULL;

  if (var_tab == NULL) {
    errno = EPERM;
    return NULL;
  }

  if (name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  v = pr_table_get(var_tab, name, NULL);
  if (v == NULL) {
    return NULL;
  }

  switch (v->v_type) {
    case PR_VAR_TYPE_STR:
      return (const char *) v->v_val;
      break;

    case PR_VAR_TYPE_FUNC:
      return ((var_vstr_cb) v->v_val)(v->v_data, v->v_datasz);
      break;

    default:
      /* Pass through to the error case. */
      pr_trace_msg(trace_channel, 9,
        "unknown var type (%d) found for name '%s'", v->v_type, name);
  }

  errno = EINVAL;
  return NULL;
}

const char *pr_var_next(const char **desc) {
  const char *name;
  const struct var *v;

  if (var_tab == NULL) {
    errno = EPERM;
    return NULL;
  }

  name = pr_table_next(var_tab);
  if (name == NULL) {
    return NULL;
  }

  v = pr_table_get(var_tab, name, NULL);
  if (v != NULL &&
      desc != NULL) {
    *desc = v->v_desc;
  }

  return name;
}

void pr_var_rewind(void) {
  if (var_tab != NULL) {
    pr_table_rewind(var_tab);
  }
}

int pr_var_set(pool *p, const char *name, const char *desc, int vtype,
    void *val, void *data, size_t datasz) {
  struct var *v;
  size_t namelen = 0;

  if (var_tab == NULL) {
    errno = EPERM;
    return -1;
  }

  if (p == NULL ||
      name == NULL ||
      val == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* The length of the key must be greater than 3 characters (for "%{}"). */
  namelen = strlen(name);
  if (namelen < 4) {
    errno = EINVAL;
    return -1;
  }

  /* If the given variable type is not recognized, reject. */
  if (vtype != PR_VAR_TYPE_STR &&
      vtype != PR_VAR_TYPE_FUNC) {
    errno = EINVAL;
    return -1;
  }

  /* Specifying data, but no length for that data, is an error. */
  if (data != NULL &&
      datasz == 0) {
    errno = EINVAL;
    return -1;
  }

  /* Specifying no data, but providing a non-zero length for that data, is an
   * error.
   */
  if (data == NULL &&
      datasz > 0) {
    errno = EINVAL;
    return -1;
  }

  /* Variable names MUST start with '%{', and end in '}'. */
  if (strncmp(name, "%{", 2) != 0 ||
      name[namelen-1] != '}') {
    errno = EINVAL;
    return -1;
  }

  /* Remove any previously registered value for this name.  For names whose
   * values change rapidly (e.g. session.xfer.total_bytes), a callback
   * function should be used, rather than always setting the same name as an
   * update; using a callback avoids the memory consumption that setting does
   * (set always allocates a new struct var *).
   */
  (void) pr_var_delete(name);

  /* Note: if var_pool was used for allocating the struct var *, rather
   * than the given pool, then deleting an entry would not necessarily
   * lead to such memory consumption (assuming it would even be a problem).
   * However, if this was the case, then a churn counter would be needed,
   * and var_pool would need to be churned occasionally to limit memory
   * growth.
   */

  switch (vtype) {
    case PR_VAR_TYPE_STR:
      v = pcalloc(p, sizeof(struct var));

      if (desc) {
        v->v_desc = (const char *) pstrdup(p, desc);
      }

      v->v_type = PR_VAR_TYPE_STR; 
      v->v_val = pstrdup(p, (char *) val);
      v->v_datasz = strlen((char *) val);
      break;

    case PR_VAR_TYPE_FUNC:
      v = pcalloc(p, sizeof(struct var));

      if (desc) {
        v->v_desc = (const char *) pstrdup(p, desc);
      }

      v->v_type = PR_VAR_TYPE_FUNC; 
      v->v_val = val;

      if (data) {
        v->v_data = data;
        v->v_datasz = datasz;
      }

      break;

    default:
      errno = EINVAL;
      return -1;
  }

  return pr_table_add(var_tab, name, v, sizeof(struct var));
}

int var_init(void) {

  if (var_pool == NULL) {
    var_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(var_pool, "Variables Pool");
  }

  if (var_tab == NULL) {
    var_tab = pr_table_alloc(var_pool, 0);
  }

  return 0;
}

int var_free(void) {
  if (var_pool) {
    if (var_tab) {
      pr_table_empty(var_tab);
      pr_table_free(var_tab);
    }

    destroy_pool(var_pool);
    var_pool = NULL;
    var_tab = NULL;
  }

  return 0;
}
