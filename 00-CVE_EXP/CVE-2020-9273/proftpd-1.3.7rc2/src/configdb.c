/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2014-2017 The ProFTPD Project team
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

/* Configuration database implementation. */

#include "conf.h"
#include "privs.h"

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

/* From src/pool.c */
extern pool *global_config_pool;

/* Used by find_config_* */
static xaset_t *find_config_top = NULL;

static void config_dumpf(const char *, ...);

static config_rec *last_param_ptr = NULL;

static pool *config_tab_pool = NULL;
static pr_table_t *config_tab = NULL;
static unsigned int config_id = 0;

static const char *trace_channel = "config";

/* Adds a config_rec to the specified set */
config_rec *pr_config_add_set(xaset_t **set, const char *name, int flags) {
  pool *conf_pool = NULL, *set_pool = NULL;
  config_rec *c, *parent = NULL;

  if (set == NULL) {
    errno = EINVAL;
    return NULL;
  }
 
  if (!*set) {

    /* Allocate a subpool from permanent_pool for the set. */
    set_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(set_pool, "config set pool");

    *set = xaset_create(set_pool, NULL);
    (*set)->pool = set_pool;

    /* Now, make a subpool for the config_rec to be allocated.  The default
     * pool size (PR_TUNABLE_NEW_POOL_SIZE, 512 by default) is a bit large
     * for config_rec pools; use a smaller size.
     */
    conf_pool = pr_pool_create_sz(set_pool, 128);

  } else {

    /* Find the parent set for the config_rec to be allocated. */
    if ((*set)->xas_list) {
      parent = ((config_rec *) ((*set)->xas_list))->parent;
    }

    /* Now, make a subpool for the config_rec to be allocated.  The default
     * pool size (PR_TUNABLE_NEW_POOL_SIZE, 512 by default) is a bit large
     * for config_rec pools; use a smaller size.  Allocate the subpool
     * from the parent's pool.
     */
    conf_pool = pr_pool_create_sz((*set)->pool, 128);
  }

  pr_pool_tag(conf_pool, "config_rec pool");

  c = (config_rec *) pcalloc(conf_pool, sizeof(config_rec));
  c->pool = conf_pool;
  c->set = *set;
  c->parent = parent;

  if (name) {
    c->name = pstrdup(conf_pool, name);
    c->config_id = pr_config_set_id(c->name);
  }

  if (flags & PR_CONFIG_FL_INSERT_HEAD) {
    xaset_insert(*set, (xasetmember_t *) c);
    
  } else {
    xaset_insert_end(*set, (xasetmember_t *) c);
  }

  return c;
}

config_rec *add_config_set(xaset_t **set, const char *name) {
  return pr_config_add_set(set, name, 0);
}

/* Adds a config_rec to the given server.  If no server is specified, the
 * config_rec is added to the current "level".
 */
config_rec *pr_config_add(server_rec *s, const char *name, int flags) {
  config_rec *parent = NULL, *c = NULL;
  pool *p = NULL;
  xaset_t **set = NULL;

  if (s == NULL) {
    s = pr_parser_server_ctxt_get();
  }

  if (s == NULL) {
    errno = EINVAL;
    return NULL;
  }

  c = pr_parser_config_ctxt_get();

  if (c) {
    parent = c;
    p = c->pool;
    set = &c->subset;

  } else {
    parent = NULL;

    if (s->conf == NULL ||
        s->conf->xas_list == NULL) {

      p = make_sub_pool(s->pool);
      pr_pool_tag(p, "pr_config_add() subpool");

    } else {
      p = ((config_rec *) s->conf->xas_list)->pool;
    }

    set = &s->conf;
  }

  if (!*set) {
    *set = xaset_create(p, NULL);
  }

  c = pr_config_add_set(set, name, flags);
  c->parent = parent;

  return c;
}

config_rec *add_config(server_rec *s, const char *name) {
  return pr_config_add(s, name, 0);
}

static void config_dumpf(const char *fmt, ...) {
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  va_list msg;

  va_start(msg, fmt);
  pr_vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[sizeof(buf)-1] = '\0';

  pr_log_debug(DEBUG5, "%s", buf);
}

void pr_config_dump(void (*dumpf)(const char *, ...), xaset_t *s,
    char *indent) {
  config_rec *c = NULL;

  if (dumpf == NULL) {
    dumpf = config_dumpf;
  }

  if (s == NULL) {
    return;
  }

  if (indent == NULL) {
    indent = "";
  }

  for (c = (config_rec *) s->xas_list; c; c = c->next) {
    pr_signals_handle();

    /* Don't display directives whose name starts with an underscore. */
    if (c->name != NULL &&
        *(c->name) != '_') {
      dumpf("%s%s", indent, c->name);
    }

    if (c->subset) {
      pr_config_dump(dumpf, c->subset, pstrcat(c->pool, indent, " ", NULL));
    }
  }
}

static const char *config_type_str(int config_type) {
  const char *type = "(unknown)";

  switch (config_type) {
    case CONF_ROOT:
      type = "CONF_ROOT";
      break;

    case CONF_DIR:
      type = "CONF_DIR";
      break;

    case CONF_ANON:
      type = "CONF_ANON";
      break;

    case CONF_LIMIT:
      type = "CONF_LIMIT";
      break;

    case CONF_VIRTUAL:
      type = "CONF_VIRTUAL";
      break;

    case CONF_DYNDIR:
      type = "CONF_DYNDIR";
      break;

    case CONF_GLOBAL:
      type = "CONF_GLOBAL";
      break;

    case CONF_CLASS:
      type = "CONF_CLASS";
      break;

    case CONF_NAMED:
      type = "CONF_NAMED";
      break;

    case CONF_USERDATA:
      type = "CONF_USERDATA";
      break;

    case CONF_PARAM:
      type = "CONF_PARAM";
      break;
  };

  return type;
}

/* Compare two different config_recs to see if they are the same.  Note
 * that "same" here has to be very specific.
 *
 * Returns 0 if the two config_recs are the same, and 1 if they differ, and
 * -1 if there was an error.
 */
static int config_cmp(const config_rec *a, const char *a_name,
    const config_rec *b, const char *b_name) {

  if (a == NULL ||
      b == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (a->config_type != b->config_type) {
    pr_trace_msg(trace_channel, 18,
      "configs '%s' and '%s' have mismatched config_type (%s != %s)",
      a_name, b_name, config_type_str(a->config_type),
      config_type_str(b->config_type));
    return 1;
  }

  if (a->flags != b->flags) {
    pr_trace_msg(trace_channel, 18,
      "configs '%s' and '%s' have mismatched flags (%ld != %ld)",
      a_name, b_name, a->flags, b->flags);
    return 1;
  }

  if (a->argc != b->argc) {
    pr_trace_msg(trace_channel, 18,
      "configs '%s' and '%s' have mismatched argc (%d != %d)",
      a_name, b_name, a->argc, b->argc);
    return 1;
  }

  if (a->argc > 0) {
    register unsigned int i;

    for (i = 0; i < a->argc; i++) {
      if (a->argv[i] != b->argv[i]) {
        pr_trace_msg(trace_channel, 18,
          "configs '%s' and '%s' have mismatched argv[%u] (%p != %p)",
          a_name, b_name, i, a->argv[i], b->argv[i]);
        return 1;
      }
    }
  }

  if (a->config_id != b->config_id) {
    pr_trace_msg(trace_channel, 18,
      "configs '%s' and '%s' have mismatched config_id (%d != %d)",
      a_name, b_name, a->config_id, b->config_id);
    return 1;
  }

  /* Save the string comparison for last, to try to save some CPU. */
  if (strcmp(a->name, b->name) != 0) {
    pr_trace_msg(trace_channel, 18,
      "configs '%s' and '%s' have mismatched name ('%s' != '%s')",
      a_name, b_name, a->name, b->name);
    return 1;
  }

  return 0;
}

static config_rec *copy_config_from(const config_rec *src, config_rec *dst) {
  config_rec *c;
  unsigned int cargc;
  void **cargv, **sargv;

  if (src == NULL ||
      dst == NULL) {
    return NULL;
  }

  /* If the destination parent config_rec doesn't already have a subset
   * container, allocate one.
   */
  if (dst->subset == NULL) {
    dst->subset = xaset_create(dst->pool, NULL);
  }

  c = pr_config_add_set(&dst->subset, src->name, 0);
  c->config_type = src->config_type;
  c->flags = src->flags;
  c->config_id = src->config_id;

  c->argc = src->argc;
  c->argv = pcalloc(c->pool, (src->argc + 1) * sizeof(void *));

  cargc = c->argc;
  cargv = c->argv;
  sargv = src->argv;

  while (cargc--) {
    pr_signals_handle();
    *cargv++ = *sargv++;
  }

  *cargv = NULL; 
  return c;
}

void pr_config_merge_down(xaset_t *s, int dynamic) {
  config_rec *c, *dst;

  if (s == NULL ||
      s->xas_list == NULL) {
    return;
  }

  for (c = (config_rec *) s->xas_list; c; c = c->next) {
    pr_signals_handle();

    if ((c->flags & CF_MERGEDOWN) ||
        (c->flags & CF_MERGEDOWN_MULTI)) {

      for (dst = (config_rec *) s->xas_list; dst; dst = dst->next) {
        if (dst->config_type == CONF_ANON ||
           dst->config_type == CONF_DIR) {

          /* If an option of the same name/type is found in the
           * next level down, it overrides, so we don't merge.
           */
          if ((c->flags & CF_MERGEDOWN) &&
              find_config(dst->subset, c->config_type, c->name, FALSE)) {
            continue;
          }

          if (dynamic) {
            /* If we are doing a dynamic merge (i.e. .ftpaccess files) then
             * we do not need to re-merge the static configs that are already
             * there.  Otherwise we are creating copies needlessly of any
             * config_rec marked with the CF_MERGEDOWN_MULTI flag, which
             * adds to the memory usage/processing time.
             *
             * If neither the src or the dst config have the CF_DYNAMIC
             * flag, it's a static config, and we can skip this merge and move
             * on.  Otherwise, we can merge it.
             */
            if (!(c->flags & CF_DYNAMIC) && !(dst->flags & CF_DYNAMIC)) {
              continue;
            }
          }

          /* We want to scan the config_recs contained in dst's subset to see
           * if we can find another config_rec that duplicates the one we want
           * to merge into dst.
           */
          if (dst->subset != NULL) {
              config_rec *r = NULL;
            int merge = TRUE;

            for (r = (config_rec *) dst->subset->xas_list; r; r = r->next) {
              pr_signals_handle();

              if (config_cmp(r, r->name, c, c->name) == 0) {
                merge = FALSE;

                pr_trace_msg(trace_channel, 15,
                  "found duplicate '%s' record in '%s', skipping merge",
                  r->name, dst->name);
                break;
              }
            }

            if (merge) {
              (void) copy_config_from(c, dst);
            }
 
          } else {
            /* No existing subset in dst; we can merge this one in. */
            (void) copy_config_from(c, dst);
          }
        }
      }
    }
  }

  /* Top level merged, recursively merge lower levels */
  for (c = (config_rec *) s->xas_list; c; c = c->next) {
    if (c->subset &&
        (c->config_type == CONF_ANON ||
         c->config_type == CONF_DIR)) {
      pr_config_merge_down(c->subset, dynamic);
    }
  }
}

config_rec *find_config_next2(config_rec *prev, config_rec *c, int type,
    const char *name, int recurse, unsigned long flags) {
  config_rec *top = c;
  unsigned int cid = 0;
  size_t namelen = 0;

  /* We do two searches (if recursing) so that we find the "deepest"
   * level first.
   *
   * The `recurse` argument tells us HOW to perform that search, e.g.
   * how to do our DFS (depth-first search) approach:
   *
   *  recurse = 0:
   *    Start at c, search all `next` nodes in list, i.e. all nodes at
   *    the same depth, no recursion.
   *
   *  recurse = 1:
   *    Start at c, search all `subset` nodes in tree first, then siblings,
   *    then `next` nodes of parent.
   *
   *  recurse > 1:
   *    Start with child nodes first (`subset`), then c itself (skipping
   *    siblings nodes).
   */

  if (c == NULL &&
      prev == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (prev == NULL) {
    prev = top;
  }

  if (name != NULL) {
    cid = pr_config_get_id(name);
    namelen = strlen(name);
  }

  do {
    if (recurse) {
      config_rec *res = NULL;

      pr_signals_handle();

      /* Search subsets. */
      for (c = top; c; c = c->next) {
        if (c->subset &&
            c->subset->xas_list) {
          config_rec *subc = NULL;

          for (subc = (config_rec *) c->subset->xas_list;
               subc;
               subc = subc->next) {
            pr_signals_handle();

            if (subc->config_type == CONF_ANON &&
                (flags & PR_CONFIG_FIND_FL_SKIP_ANON)) {
              /* Skip <Anonymous> config_rec */
              continue;
            }

            if (subc->config_type == CONF_DIR &&
                (flags & PR_CONFIG_FIND_FL_SKIP_DIR)) {
              /* Skip <Directory> config_rec */
              continue;
            }

            if (subc->config_type == CONF_LIMIT &&
                (flags & PR_CONFIG_FIND_FL_SKIP_LIMIT)) {
              /* Skip <Limit> config_rec */
              continue;
            }

            if (subc->config_type == CONF_DYNDIR &&
                (flags & PR_CONFIG_FIND_FL_SKIP_DYNDIR)) {
              /* Skip .ftpaccess config_rec */
              continue;
            }

            res = find_config_next2(NULL, subc, type, name, recurse + 1, flags);
            if (res) {
              return res;
            }
          }
        }

        if (recurse > 1) {
          /* Sibling subsets are already searched by the caller; no need to
           * continue here (Bug#4307).
           */
          break;
        }
      }
    }

    /* Recurse: If deep recursion yielded no match try the current subset.
     *
     * NOTE: the string comparison here is specifically case-sensitive.
     * The config_rec names are supplied by the modules and intentionally
     * case sensitive (they shouldn't be verbatim from the config file)
     * Do NOT change this to strcasecmp(), no matter how tempted you are
     * to do so, it will break stuff. ;)
     */
    for (c = top; c; c = c->next) {
      pr_signals_handle();

      if (type == -1 ||
          type == c->config_type) {

        if (name == NULL) {
          return c;
        }

        if (cid != 0 &&
            cid == c->config_id) {
          return c;
        }

        if (strncmp(name, c->name, namelen + 1) == 0) {
          return c;
        }
      }

      if (recurse > 1) {
        /* Sibling subsets are already searched by the caller; no need to
         * continue here (Bug#4307).
         */
        break;
      }
    }

    if (recurse == 1) {
      /* All siblings have been searched; continue the search at the previous
       * level.
       */
      if (prev->parent &&
          prev->parent->next &&
          prev->parent->set != find_config_top) {
        prev = top = prev->parent->next;
        c = top;
        continue;
      }
    }
    break;

  } while (TRUE);

  errno = ENOENT;
  return NULL;
}

config_rec *find_config_next(config_rec *prev, config_rec *c, int type,
    const char *name, int recurse) {
  return find_config_next2(prev, c, type, name, recurse, 0UL);
}

void find_config_set_top(config_rec *c) {
  if (c &&
      c->parent) {
    find_config_top = c->parent->set;

  } else {
    find_config_top = NULL;
  }
}

config_rec *find_config2(xaset_t *set, int type, const char *name,
  int recurse, unsigned long flags) {

  if (set == NULL ||
      set->xas_list == NULL) {
    errno = EINVAL;
    return NULL;
  }

  find_config_set_top((config_rec *) set->xas_list);

  return find_config_next2(NULL, (config_rec *) set->xas_list, type, name,
    recurse, flags);
}

config_rec *find_config(xaset_t *set, int type, const char *name, int recurse) {
  return find_config2(set, type, name, recurse, 0UL);
}

void *get_param_ptr(xaset_t *set, const char *name, int recurse) {
  config_rec *c;

  if (set == NULL) {
    last_param_ptr = NULL;
    errno = ENOENT;
    return NULL;
  }

  c = find_config(set, CONF_PARAM, name, recurse);
  if (c &&
      c->argc) {
    last_param_ptr = c;
    return c->argv[0];
  }

  last_param_ptr = NULL;
  errno = ENOENT;
  return NULL;
}

void *get_param_ptr_next(const char *name, int recurse) {
  config_rec *c;

  if (!last_param_ptr ||
      !last_param_ptr->next) {
    last_param_ptr = NULL;
    errno = ENOENT; 
    return NULL;
  }

  c = find_config_next(last_param_ptr, last_param_ptr->next, CONF_PARAM,
    name, recurse);
  if (c &&
      c->argv) {
    last_param_ptr = c;
    return c->argv[0];
  }

  last_param_ptr = NULL;
  errno = ENOENT;
  return NULL;
}

int pr_config_remove(xaset_t *set, const char *name, int flags, int recurse) {
  server_rec *s;
  config_rec *c;
  int found = 0;
  xaset_t *found_set;

  s = pr_parser_server_ctxt_get();
  if (s == NULL) {
    s = main_server;
  }

  while ((c = find_config(set, -1, name, recurse)) != NULL) {
    pr_signals_handle();

    found++;

    found_set = c->set;
    xaset_remove(found_set, (xasetmember_t *) c);

    /* If the set is empty, and has no more contained members in the xas_list,
     * destroy the set.
     */
    if (!found_set->xas_list) {

      /* First, set any pointers to the container of the set to NULL. */
      if (c->parent &&
          c->parent->subset == found_set) {
        c->parent->subset = NULL;

      } else if (s && s->conf == found_set) {
        s->conf = NULL;
      }

      if (!(flags & PR_CONFIG_FL_PRESERVE_ENTRY)) {
        /* Next, destroy the set's pool, which destroys the set as well. */
        destroy_pool(found_set->pool);
      }

    } else {
      if (!(flags & PR_CONFIG_FL_PRESERVE_ENTRY)) {
        /* If the set was not empty, destroy only the requested config_rec. */
        destroy_pool(c->pool);
      }
    }
  }

  return found;
}

int remove_config(xaset_t *set, const char *name, int recurse) {
  return pr_config_remove(set, name, 0, recurse);
}

config_rec *add_config_param_set(xaset_t **set, const char *name,
    unsigned int num, ...) {
  config_rec *c;
  void **argv;
  va_list ap;

  c = pr_config_add_set(set, name, 0);
  if (c == NULL) {
    return NULL;
  }

  c->config_type = CONF_PARAM;
  c->argc = num;
  c->argv = pcalloc(c->pool, (num+1) * sizeof(void *));

  argv = c->argv;
  va_start(ap,num);

  while (num-- > 0) {
    *argv++ = va_arg(ap, void *);
  }

  va_end(ap);

  return c;
}

config_rec *add_config_param_str(const char *name, unsigned int num, ...) {
  config_rec *c;
  char *arg = NULL;
  void **argv = NULL;
  va_list ap;

  c = pr_config_add(NULL, name, 0);
  if (c != NULL) {
    c->config_type = CONF_PARAM;
    c->argc = num;
    c->argv = pcalloc(c->pool, (num+1) * sizeof(char *));

    argv = c->argv;
    va_start(ap, num);

    while (num-- > 0) {
      arg = va_arg(ap, char *);
      if (arg) {
        *argv++ = pstrdup(c->pool, arg);

      } else {
        *argv++ = NULL;
      }
    }

    va_end(ap);
  }

  return c;
}

config_rec *pr_conf_add_server_config_param_str(server_rec *s, const char *name,
    unsigned int num, ...) {
  config_rec *c;
  char *arg = NULL;
  void **argv = NULL;
  va_list ap;

  c = pr_config_add(s, name, 0);
  if (c == NULL) {
    return NULL;
  }

  c->config_type = CONF_PARAM;
  c->argc = num;
  c->argv = pcalloc(c->pool, (num+1) * sizeof(char *));

  argv = c->argv;
  va_start(ap, num);

  while (num-- > 0) {
    arg = va_arg(ap, char *);
    if (arg) {
      *argv++ = pstrdup(c->pool, arg);

    } else {
      *argv++ = NULL;
    }
  }

  va_end(ap);
  return c;
}

config_rec *add_config_param(const char *name, unsigned int num, ...) {
  config_rec *c;
  void **argv;
  va_list ap;

  if (name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  c = pr_config_add(NULL, name, 0);
  if (c) {
    c->config_type = CONF_PARAM;
    c->argc = num;
    c->argv = pcalloc(c->pool, (num+1) * sizeof(void*));

    argv = c->argv;
    va_start(ap, num);

    while (num-- > 0) {
      *argv++ = va_arg(ap, void *);
    }

    va_end(ap);
  }

  return c;
}

unsigned int pr_config_get_id(const char *name) {
  const void *ptr = NULL;
  unsigned int id = 0;

  if (name == NULL) {
    errno = EINVAL;
    return 0;
  }

  if (config_tab == NULL) {
    errno = EPERM;
    return 0;
  }

  ptr = pr_table_get(config_tab, name, NULL);
  if (ptr == NULL) {
    errno = ENOENT;
    return 0;
  }

  id = *((unsigned int *) ptr);
  return id;
}

unsigned int pr_config_set_id(const char *name) {
  unsigned int *ptr = NULL;
  unsigned int id;

  if (!name) {
    errno = EINVAL;
    return 0;
  }

  if (!config_tab) {
    errno = EPERM;
    return 0;
  }

  ptr = pr_table_pcalloc(config_tab, sizeof(unsigned int));
  *ptr = ++config_id;

  if (pr_table_add(config_tab, name, ptr, sizeof(unsigned int *)) < 0) {
    if (errno == EEXIST) {
      id = pr_config_get_id(name);

    } else {
      if (errno == ENOSPC) {
        pr_log_debug(DEBUG9,
         "error adding '%s' to config ID table: table is full", name);

      } else {
        pr_log_debug(DEBUG9, "error adding '%s' to config ID table: %s",
          name, strerror(errno));
      }

      return 0;
    }

  } else {
    id = *ptr;
  }

  return id;
}

void init_config(void) {
  unsigned int maxents;

  /* Make sure global_config_pool is destroyed */
  if (global_config_pool) {
    destroy_pool(global_config_pool);
    global_config_pool = NULL;
  }

  if (config_tab) {
    /* Clear the existing config ID table.  This needs to happen when proftpd
     * is restarting.
     */
    if (pr_table_empty(config_tab) < 0) {
      pr_log_debug(DEBUG0, "error emptying config ID table: %s",
        strerror(errno));
    }

    if (pr_table_free(config_tab) < 0) {
      pr_log_debug(DEBUG0, "error destroying config ID table: %s",
        strerror(errno));
    }

    config_tab = pr_table_alloc(config_tab_pool, 0);

    /* Reset the ID counter as well.  Otherwise, an exceedingly long-lived
     * proftpd, restarted many times, has the possibility of overflowing
     * the counter data type.
     */
    config_id = 0;

  } else {

    config_tab_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(config_tab_pool, "Config Table Pool");
    config_tab = pr_table_alloc(config_tab_pool, 0);
  }

  /* Increase the max "size" of the table; some configurations can lead
   * to a large number of configuration directives.
   */
  maxents = 32768;

  if (pr_table_ctl(config_tab, PR_TABLE_CTL_SET_MAX_ENTS, &maxents) < 0) {
    pr_log_debug(DEBUG2, "error setting config ID table max size to %u: %s",
      maxents, strerror(errno));
  }

  return;
}
