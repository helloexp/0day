/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2010-2017 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project and other respective copyright
 * holders give permission to link this program with OpenSSL, and distribute
 * the resulting executable, without including the source code for OpenSSL in
 * the source distribution.
 */

/* Symbol table hashes */

#include "conf.h"

#ifndef PR_SYM_POOL_SIZE
# define PR_SYM_POOL_SIZE		128
#endif /* PR_SYM_POOL_SIZE */

/* This local structure vastly speeds up symbol lookups. */
struct stash {
  struct stash *next, *prev;
  pool *sym_pool;
  unsigned int sym_hash;
  const char *sym_name;
  size_t sym_namelen;
  pr_stash_type_t sym_type;
  module *sym_module;

  union {
    conftable *sym_conf;
    cmdtable *sym_cmd;
    authtable *sym_auth;
    cmdtable *sym_hook;
    void *sym_generic;
  } ptr;
};

static pool *symbol_pool = NULL;

/* Symbol hashes for each type */
static xaset_t *conf_symbol_table[PR_TUNABLE_HASH_TABLE_SIZE];
static struct stash *conf_curr_sym = NULL;

static xaset_t *cmd_symbol_table[PR_TUNABLE_HASH_TABLE_SIZE];
static struct stash *cmd_curr_sym = NULL;

static xaset_t *auth_symbol_table[PR_TUNABLE_HASH_TABLE_SIZE];
static struct stash *auth_curr_sym = NULL;

static xaset_t *hook_symbol_table[PR_TUNABLE_HASH_TABLE_SIZE];
static struct stash *hook_curr_sym = NULL;

/* Symbol stash lookup code and management */

static struct stash *sym_alloc(void) {
  pool *sub_pool;
  struct stash *sym;

  /* XXX Use a smaller pool size, since there are lots of sub-pools allocated
   * for Stash symbols.  The default pool size (PR_TUNABLE_POOL_SIZE, 512
   * bytes by default) is a bit large for symbols.
   */
  sub_pool = pr_pool_create_sz(symbol_pool, PR_SYM_POOL_SIZE);

  sym = pcalloc(sub_pool, sizeof(struct stash));
  sym->sym_pool = sub_pool; 
  pr_pool_tag(sub_pool, "symbol");

  return sym;
}

static int sym_cmp(struct stash *s1, struct stash *s2) {
  int res;
  size_t checked_len = 0, namelen;

  if (s1->sym_hash != s2->sym_hash) {
    return s1->sym_hash < s2->sym_hash ? -1 : 1;
  }

  if (s1->sym_namelen != s2->sym_namelen) {
    return s1->sym_namelen < s2->sym_namelen ? -1 : 1;
  }

  namelen = s1->sym_namelen;

  /* Try to avoid strncmp(3) if we can. */
  if (namelen >= 2) {
    char c1, c2;

    c1 = s1->sym_name[0];
    c2 = s2->sym_name[0];

    if (c1 != c2) {
      return c1 < c2 ? -1 : 1;
    }

    checked_len++;

    if (namelen >= 3) {
      c1 = s1->sym_name[1];
      c2 = s2->sym_name[1];

      if (c1 != c2) {
        return c1 < c2 ? -1 : 1;
      }

      checked_len++;
    }
  }

  res = strncmp(s1->sym_name + checked_len, s2->sym_name + checked_len,
    namelen - checked_len);

  /* Higher priority modules must go BEFORE lower priority in the
   * hash tables.
   */

  if (res == 0) {
    if (s1->sym_module != NULL &&
        s2->sym_module != NULL) {

      if (s1->sym_module->priority > s2->sym_module->priority) {
        return -1;
      }
    
      if (s1->sym_module->priority < s2->sym_module->priority) {
        return 1;
      }

      return res;
    }

    if (s1->sym_module != NULL &&
        s2->sym_module == NULL) {
      return -1;
    }

    if (s1->sym_module == NULL &&
        s2->sym_module != NULL) {
      return 1;
    }

    /* Both sym_module fields are null. */
    return 0;
  }

  return res;
}

static unsigned int symtab_hash(const char *name, size_t namelen) {
  register unsigned int i;
  unsigned int h = 0;

  if (name == NULL) {
    return 0;
  }

  for (i = 0; i < namelen; i++) {
    const char *cp;

    cp = (const char *) &(name[i]);
    h = (h * 33) + *cp;
  }

  return h;
}

static unsigned int sym_type_hash(pr_stash_type_t sym_type, const char *name,
    size_t namelen) {
  unsigned int hash;

  /* XXX Ugly hack to support mixed cases of directives in config files. */
  if (sym_type != PR_SYM_CONF) {
    hash = symtab_hash(name, namelen);

  } else {
    register unsigned int i;
    char *buf;

    buf = malloc(namelen+1);
    if (buf == NULL) {
      pr_log_pri(PR_LOG_ALERT, "Out of memory!");
      exit(1);
    }

    buf[namelen] = '\0';
    for (i = 0; i < namelen; i++) {
      buf[i] = tolower((int) name[i]);
    }

    hash = symtab_hash(buf, namelen);
    free(buf);
  }

  return hash;
}

int pr_stash_add_symbol(pr_stash_type_t sym_type, void *data) {
  struct stash *sym = NULL;
  unsigned int hash;
  int idx = 0;
  xaset_t **symbol_table;
  size_t sym_namelen = 0;

  if (data == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (sym_type) {
    case PR_SYM_CONF:
      sym = sym_alloc();
      sym->sym_type = PR_SYM_CONF;
      sym->sym_name = ((conftable *) data)->directive;
      sym->sym_module = ((conftable *) data)->m;
      sym->ptr.sym_conf = data;
      symbol_table = conf_symbol_table;
      break;

    case PR_SYM_CMD:
      sym = sym_alloc();
      sym->sym_type = PR_SYM_CMD;
      sym->sym_name = ((cmdtable *) data)->command;
      sym->sym_module = ((cmdtable *) data)->m;
      sym->ptr.sym_cmd = data;
      symbol_table = cmd_symbol_table;
      break;

    case PR_SYM_AUTH:
      sym = sym_alloc();
      sym->sym_type = PR_SYM_AUTH;
      sym->sym_name = ((authtable *) data)->name;
      sym->sym_module = ((authtable *) data)->m;
      sym->ptr.sym_auth = data;
      symbol_table = auth_symbol_table;
      break;

    case PR_SYM_HOOK:
      sym = sym_alloc();
      sym->sym_type = PR_SYM_HOOK;
      sym->sym_name = ((cmdtable *) data)->command;
      sym->sym_module = ((cmdtable *) data)->m;
      sym->ptr.sym_hook = data;
      symbol_table = hook_symbol_table;
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  /* XXX Should we check for null sym->sym_module as well? */
  if (sym->sym_name == NULL) {
    destroy_pool(sym->sym_pool);
    errno = EPERM;
    return -1;
  }

  sym_namelen = strlen(sym->sym_name);
  if (sym_namelen == 0) {
    destroy_pool(sym->sym_pool);
    errno = EPERM;
    return -1;
  }

  /* Don't forget to include one for the terminating NUL. */
  sym->sym_namelen = sym_namelen + 1;

  hash = sym_type_hash(sym_type, sym->sym_name, sym->sym_namelen);
  idx = hash % PR_TUNABLE_HASH_TABLE_SIZE;
  sym->sym_hash = hash;

  if (!symbol_table[idx]) {
    symbol_table[idx] = xaset_create(symbol_pool, (XASET_COMPARE) sym_cmp);
  }

  xaset_insert_sort(symbol_table[idx], (xasetmember_t *) sym, TRUE);
  return 0;
}

static struct stash *stash_lookup(pr_stash_type_t sym_type,
    const char *name, size_t namelen, int idx, unsigned int hash) {
  struct stash *sym = NULL;
  xaset_t **symbol_table = NULL;

  switch (sym_type) {
    case PR_SYM_CONF:
      symbol_table = conf_symbol_table;
      break;

    case PR_SYM_CMD:
      symbol_table = cmd_symbol_table;
      break;

    case PR_SYM_AUTH:
      symbol_table = auth_symbol_table;
      break;

    case PR_SYM_HOOK:
      symbol_table = hook_symbol_table;
      break;

    default:
      errno = EINVAL;
      return NULL;
  }

  if (symbol_table[idx]) {
    for (sym = (struct stash *) symbol_table[idx]->xas_list; sym;
        sym = sym->next) {
      int res;

      if (name == NULL) {
        break;
      }

      if (sym->sym_hash != hash) {
        continue;
      }

      if (sym->sym_namelen != namelen) {
        continue;
      }

      /* Try to avoid strncmp(3) if we can. */
      if (namelen >= 1) {
        char c1, c2;

        c1 = tolower((int) sym->sym_name[0]);
        c2 = tolower((int) name[0]);

        if (c1 != c2) {
          continue;
        }

        /* Special case (unlikely, but possible) */
        if (namelen == 1 &&
            c1 == '\0') {
          break;
        }
      }

      if (namelen >= 2) {
        char c1, c2;

        c1 = tolower((int) sym->sym_name[1]);
        c2 = tolower((int) name[1]);

        if (c1 != c2) {
          continue;
        }

        /* Special case */
        if (namelen == 2 &&
            c1 == '\0') {
          break;
        }
      }

      res = strncasecmp(sym->sym_name + 2, name + 2, namelen - 2);
      if (res == 0) {
        break;
      }
    }
  }

  return sym;
}

static struct stash *stash_lookup_next(pr_stash_type_t sym_type,
    const char *name, size_t namelen, int idx, unsigned int hash, void *prev) {
  struct stash *sym = NULL;
  int last_hit = 0;
  xaset_t **symbol_table = NULL;

  switch (sym_type) {
    case PR_SYM_CONF:
      symbol_table = conf_symbol_table;
      break;

    case PR_SYM_CMD:
      symbol_table = cmd_symbol_table;
      break;

    case PR_SYM_AUTH:
      symbol_table = auth_symbol_table;
      break;

    case PR_SYM_HOOK:
      symbol_table = hook_symbol_table;
      break;

    default:
      errno = EINVAL;
      return NULL;
  }

  if (symbol_table[idx]) {
    for (sym = (struct stash *) symbol_table[idx]->xas_list; sym;
        sym = sym->next) {
      if (last_hit) {
        int res;

        if (name == NULL) {
          break;
        }

        if (sym->sym_hash != hash) {
          continue;
        }

        if (sym->sym_namelen != namelen) {
          continue;
        }

        /* Try to avoid strncmp(3) if we can. */
        if (namelen >= 1) {
          char c1, c2;

          c1 = tolower((int) sym->sym_name[0]);
          c2 = tolower((int) name[0]);

          if (c1 != c2) {
            continue;
          }

          /* Special case (unlikely, but possible) */
          if (namelen == 1 &&
              c1 == '\0') {
            break;
          }
        }

        if (namelen >= 2) {
          char c1, c2;

          c1 = tolower((int) sym->sym_name[1]);
          c2 = tolower((int) name[1]);

          if (c1 != c2) {
            continue;
          }

          /* Special case */
          if (namelen == 2 &&
              c1 == '\0') {
            break;
          }
        }

        res = strncasecmp(sym->sym_name + 2, name + 2, namelen - 2);
        if (res == 0) {
          break;
        }
      }

      if (sym->ptr.sym_generic == prev) {
        last_hit++;
      }
    }
  }

  return sym;
}

void *pr_stash_get_symbol2(pr_stash_type_t sym_type, const char *name,
    void *prev, int *idx_cache, unsigned int *hash_cache) {
  int idx;
  unsigned int hash = 0;
  struct stash *sym = NULL;
  size_t namelen = 0;

  if (sym_type != PR_SYM_CONF &&
      sym_type != PR_SYM_CMD &&
      sym_type != PR_SYM_AUTH &&
      sym_type != PR_SYM_HOOK) {
    errno = EINVAL;
    return NULL;
  }

  if (name != NULL) {
    /* Don't forget to include one for the terminating NUL. */
    namelen = strlen(name) + 1;
  }

  if (idx_cache != NULL &&
      *idx_cache != -1) {
    idx = *idx_cache;

    if (hash_cache != NULL) {
      hash = *hash_cache;
      if (hash == 0) {
        hash = sym_type_hash(sym_type, name, namelen);
        *hash_cache = hash;
      }

    } else {
      hash = sym_type_hash(sym_type, name, namelen);
    }

  } else {
    hash = sym_type_hash(sym_type, name, namelen);
    idx = hash % PR_TUNABLE_HASH_TABLE_SIZE;

    if (idx_cache != NULL) {
      *idx_cache = idx;
    }

    if (hash_cache != NULL) {
      *hash_cache = hash;
    }
  }

  if (idx >= PR_TUNABLE_HASH_TABLE_SIZE) {
    if (idx_cache != NULL) {
      *idx_cache = -1;
    }

    if (hash_cache != NULL) {
      *hash_cache = 0;
    }

    errno = EINVAL;
    return NULL;
  }

  if (prev) {
    sym = stash_lookup_next(sym_type, name, namelen, idx, hash, prev);

  } else {
    sym = stash_lookup(sym_type, name, namelen, idx, hash);
  }

  switch (sym_type) {
    case PR_SYM_CONF:
      conf_curr_sym = sym;
      if (sym) {
        return sym->ptr.sym_conf;
      }

      errno = ENOENT;
      return NULL;

    case PR_SYM_CMD:
      cmd_curr_sym = sym;
      if (sym) {
        return sym->ptr.sym_cmd;
      }

      errno = ENOENT;
      return NULL;

    case PR_SYM_AUTH:
      auth_curr_sym = sym;
      if (sym) {
        return sym->ptr.sym_auth;
      }

      errno = ENOENT;
      return NULL;

    case PR_SYM_HOOK:
      hook_curr_sym = sym;
      if (sym) {
        return sym->ptr.sym_hook;
      }

      errno = ENOENT;
      return NULL;
  }

  errno = EINVAL;
  return NULL;
}

void *pr_stash_get_symbol(pr_stash_type_t sym_type, const char *name,
    void *prev, int *idx_cache) {
  return pr_stash_get_symbol2(sym_type, name, prev, idx_cache, NULL);
}

int pr_stash_remove_conf(const char *directive_name, module *m) {
  int count = 0, prev_idx, symtab_idx = 0;
  size_t directive_namelen = 0;
  unsigned int hash;
  conftable *tab = NULL;

  if (directive_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Don't forget to include one for the terminating NUL. */
  directive_namelen = strlen(directive_name) + 1;

  hash = sym_type_hash(PR_SYM_CONF, directive_name, directive_namelen);
  symtab_idx = hash % PR_TUNABLE_HASH_TABLE_SIZE;
  prev_idx = -1;

  tab = pr_stash_get_symbol2(PR_SYM_CONF, directive_name, NULL, &prev_idx,
    &hash);
  while (tab) {
    pr_signals_handle();

    /* Note: this works because of a hack: the symbol lookup functions set a
     * static pointer, conf_curr_sym, to point to the struct stash just looked
     * up.  conf_curr_sym will not be NULL if pr_stash_get_symbol2() returns
     * non-NULL.
     */

    if (m == NULL ||
        conf_curr_sym->sym_module == m) {
      xaset_remove(conf_symbol_table[symtab_idx],
        (xasetmember_t *) conf_curr_sym);
      destroy_pool(conf_curr_sym->sym_pool);
      conf_curr_sym = NULL;
      tab = NULL;
      count++;
    }

    tab = pr_stash_get_symbol2(PR_SYM_CONF, directive_name, tab, &prev_idx,
      &hash);
  }

  return count;
}

/* Sentinel values:
 *
 *  cmd_type = 0
 *  cmd_group = NULL
 *  cmd_class = -1
 */
int pr_stash_remove_cmd(const char *cmd_name, module *m,
    unsigned char cmd_type, const char *cmd_group, int cmd_class) {
  int count = 0, prev_idx, symtab_idx = 0;
  size_t cmd_namelen = 0;
  unsigned int hash;
  cmdtable *tab = NULL;

  if (cmd_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Don't forget to include one for the terminating NUL. */
  cmd_namelen = strlen(cmd_name) + 1;

  hash = sym_type_hash(PR_SYM_CMD, cmd_name, cmd_namelen);
  symtab_idx = hash % PR_TUNABLE_HASH_TABLE_SIZE;
  prev_idx = -1;

  tab = pr_stash_get_symbol2(PR_SYM_CMD, cmd_name, NULL, &prev_idx, &hash);
  while (tab) {
    cmdtable *cmd_sym;

    pr_signals_handle();

    /* Note: this works because of a hack: the symbol lookup functions set a
     * static pointer, cmd_curr_sym, to point to the struct stash just looked
     * up.  cmd_curr_sym will not be NULL if pr_stash_get_symbol2() returns
     * non-NULL.
     */

    cmd_sym = cmd_curr_sym->ptr.sym_cmd;
    if ((m == NULL || cmd_curr_sym->sym_module == m) &&
        (cmd_type == 0 || cmd_sym->cmd_type == cmd_type) &&
        (cmd_group == NULL ||
         (cmd_group != NULL &&
          cmd_sym->group != NULL &&
          strcmp(cmd_sym->group, cmd_group) == 0)) &&
        (cmd_class == -1 || cmd_sym->cmd_class == cmd_class)) {
      xaset_remove(cmd_symbol_table[symtab_idx],
        (xasetmember_t *) cmd_curr_sym);
      destroy_pool(cmd_curr_sym->sym_pool);
      cmd_curr_sym = NULL;
      tab = NULL;
      count++;
    }

    tab = pr_stash_get_symbol2(PR_SYM_CMD, cmd_name, tab, &prev_idx, &hash);
  }

  return count;
}

int pr_stash_remove_auth(const char *api_name, module *m) {
  int count = 0, prev_idx, symtab_idx = 0;
  size_t api_namelen = 0;
  unsigned int hash;
  authtable *tab = NULL;

  if (api_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Don't forget to include one for the terminating NUL. */
  api_namelen = strlen(api_name) + 1;

  hash = sym_type_hash(PR_SYM_AUTH, api_name, api_namelen);
  symtab_idx = hash % PR_TUNABLE_HASH_TABLE_SIZE;
  prev_idx = -1;

  tab = pr_stash_get_symbol2(PR_SYM_AUTH, api_name, NULL, &prev_idx, &hash);
  while (tab) {
    pr_signals_handle();

    /* Note: this works because of a hack: the symbol lookup functions set a
     * static pointer, auth_curr_sym, to point to the struct stash just looked
     * up.  auth_curr_sym will not be NULL if pr_stash_get_symbol2() returns
     * non-NULL.
     */

    if (m == NULL ||
        auth_curr_sym->sym_module == m) {
      xaset_remove(auth_symbol_table[symtab_idx],
        (xasetmember_t *) auth_curr_sym);
      destroy_pool(auth_curr_sym->sym_pool);
      auth_curr_sym = NULL;
      tab = NULL;
      count++;
    }

    tab = pr_stash_get_symbol2(PR_SYM_AUTH, api_name, tab, &prev_idx, &hash);
  }

  return count;
}

int pr_stash_remove_hook(const char *hook_name, module *m) {
  int count = 0, prev_idx, symtab_idx = 0;
  size_t hook_namelen = 0;
  unsigned int hash;
  cmdtable *tab = NULL;

  if (hook_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Don't forget to include one for the terminating NUL. */
  hook_namelen = strlen(hook_name) + 1;

  hash = sym_type_hash(PR_SYM_HOOK, hook_name, hook_namelen);
  symtab_idx = hash % PR_TUNABLE_HASH_TABLE_SIZE;
  prev_idx = -1;

  tab = pr_stash_get_symbol2(PR_SYM_HOOK, hook_name, NULL, &prev_idx, &hash);
  while (tab) {
    pr_signals_handle();

    /* Note: this works because of a hack: the symbol lookup functions set a
     * static pointer, hook_curr_sym, to point to the struct stash just looked
     * up.  hook_curr_sym will not be NULL if pr_stash_get_symbol2() returns
     * non-NULL.
     */

    if (m == NULL ||
        hook_curr_sym->sym_module == m) {
      xaset_remove(hook_symbol_table[symtab_idx],
        (xasetmember_t *) hook_curr_sym);
      destroy_pool(hook_curr_sym->sym_pool);
      hook_curr_sym = NULL;
      tab = NULL;
      count++;
    }

    tab = pr_stash_get_symbol2(PR_SYM_HOOK, hook_name, tab, &prev_idx, &hash);
  }

  return count;
}

int pr_stash_remove_symbol(pr_stash_type_t sym_type, const char *sym_name,
    module *sym_module) {
  int count = 0;

  switch (sym_type) {
    case PR_SYM_CONF:
      count = pr_stash_remove_conf(sym_name, sym_module);
      break;

    case PR_SYM_CMD:
      count = pr_stash_remove_cmd(sym_name, sym_module, 0, NULL, -1);
      break;

    case PR_SYM_AUTH:
      count = pr_stash_remove_auth(sym_name, sym_module);
      break;

    case PR_SYM_HOOK:
      count = pr_stash_remove_hook(sym_name, sym_module);
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  return count;
}

#ifdef PR_USE_DEVEL
static void stash_dumpf(const char *fmt, ...) {
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  va_list msg;

  va_start(msg, fmt);
  pr_vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[sizeof(buf)-1] = '\0';

  pr_log_debug(DEBUG5, "%s", buf);
}
#endif

#ifdef PR_USE_DEVEL
static unsigned int stash_dump_syms(xaset_t **symbol_table, const char *type,
    void (*dumpf)(const char *, ...)) {
  register unsigned int i;
  unsigned int count = 0;

  for (i = 0; i < PR_TUNABLE_HASH_TABLE_SIZE; i++) {
    unsigned int nrow_syms = 0;
    struct stash *sym;
    xaset_t *syms;

    pr_signals_handle();

    syms = symbol_table[i];
    if (syms == NULL) {
      continue;
    }

    for (sym = (struct stash *) syms->xas_list; sym; sym = sym->next) {
      nrow_syms++;
    }

    dumpf("%s stab index %u: %u symbols", type, i, nrow_syms);

    for (sym = (struct stash *) syms->xas_list; sym; sym = sym->next) {
      count++;

      if (sym->sym_module != NULL) {
        dumpf(" + %s symbol: %s (mod_%s.c)", type, sym->sym_name,
          sym->sym_module->name);

      } else {
        dumpf(" + %s symbol: %s (core)", type, sym->sym_name);
      }
    }
  }

  return count;
}
#endif /* PR_USE_DEVEL */

void pr_stash_dump(void (*dumpf)(const char *, ...)) {
#ifdef PR_USE_DEVEL
  unsigned int nsyms = 0, nconf_syms = 0, ncmd_syms = 0, nauth_syms = 0,
    nhook_syms = 0;

  if (dumpf == NULL) {
    dumpf = stash_dumpf;
  }

  nconf_syms = stash_dump_syms(conf_symbol_table, "CONF", dumpf);
  ncmd_syms = stash_dump_syms(cmd_symbol_table, "CMD", dumpf);
  nauth_syms = stash_dump_syms(auth_symbol_table, "AUTH", dumpf);
  nhook_syms = stash_dump_syms(hook_symbol_table, "HOOK", dumpf);
  nsyms = nconf_syms + ncmd_syms + nauth_syms + nhook_syms;
 
  dumpf("stab: %u total symbols: %u CONF, %u CMD, %u AUTH, %u HOOK", nsyms,
    nconf_syms, ncmd_syms, nauth_syms, nhook_syms);

#endif /* PR_USE_DEVEL */
}

int init_stash(void) {
  if (symbol_pool != NULL) {
    destroy_pool(symbol_pool);
  }

  symbol_pool = make_sub_pool(permanent_pool); 
  pr_pool_tag(symbol_pool, "Stash Pool");

  memset(conf_symbol_table, '\0', sizeof(conf_symbol_table));
  memset(cmd_symbol_table, '\0', sizeof(cmd_symbol_table));
  memset(auth_symbol_table, '\0', sizeof(auth_symbol_table));
  memset(hook_symbol_table, '\0', sizeof(hook_symbol_table));

  return 0;
}
