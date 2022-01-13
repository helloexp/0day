/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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

/* Module handling routines */

#include "conf.h"

extern module *static_modules[];
extern module *loaded_modules;

/* Currently running module */
module *curr_module = NULL;
  
/* Used to track the priority for loaded modules. */
static unsigned int curr_module_pri = 0;

static const char *trace_channel = "module";
  
modret_t *pr_module_call(module *m, modret_t *(*func)(cmd_rec *),
    cmd_rec *cmd) {
  modret_t *res;
  module *prev_module = curr_module;

  if (m == NULL ||
      func == NULL ||
      cmd == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (cmd->tmp_pool == NULL) {
    cmd->tmp_pool = make_sub_pool(cmd->pool);
    pr_pool_tag(cmd->tmp_pool, "Module call tmp_pool");
  }

  curr_module = m;
  res = func(cmd);
  curr_module = prev_module;

  /* Note that we don't clear the pool here because the function may
   * return data which resides in this pool.
   */
  return res;
}

modret_t *mod_create_data(cmd_rec *cmd, void *d) {
  modret_t *res;

  if (cmd == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = pcalloc(cmd->tmp_pool, sizeof(modret_t));
  res->data = d;

  return res;
}

modret_t *mod_create_ret(cmd_rec *cmd, unsigned char err, const char *n,
    const char *m) {
  modret_t *res;

  if (cmd == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = pcalloc(cmd->tmp_pool, sizeof(modret_t));
  res->mr_handler_module = curr_module;
  res->mr_error = err;

  if (n != NULL) {
    res->mr_numeric = pstrdup(cmd->tmp_pool, n);
  }

  if (m != NULL) {
    res->mr_message = pstrdup(cmd->tmp_pool, m);
  }

  return res;
}

modret_t *mod_create_error(cmd_rec *cmd, int mr_errno) {
  modret_t *res;

  if (cmd == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = pcalloc(cmd->tmp_pool, sizeof(modret_t));
  res->mr_handler_module = curr_module;
  res->mr_error = mr_errno;

  return res;
}

/* Called after forking in order to inform/initialize modules
 * need to know we are a child and have a connection.
 */
int modules_session_init(void) {
  module *prev_module = curr_module, *m;

  for (m = loaded_modules; m; m = m->next) {
    if (m->sess_init) {
      curr_module = m;

      pr_trace_msg(trace_channel, 12,
        "invoking sess_init callback on mod_%s.c", m->name);
      if (m->sess_init() < 0) {
        int xerrno = errno;

        pr_log_pri(PR_LOG_WARNING, "mod_%s.c: error initializing session: %s",
          m->name, strerror(xerrno));

        errno = xerrno;
        return -1;
      }
    }
  }

  curr_module = prev_module;
  return 0;
}

unsigned char command_exists(const char *name) {
  int idx = -1;
  unsigned int hash = 0;
  cmdtable *cmdtab;

  cmdtab = pr_stash_get_symbol2(PR_SYM_CMD, name, NULL, &idx, &hash);
  while (cmdtab && cmdtab->cmd_type != CMD) {
    pr_signals_handle();
    cmdtab = pr_stash_get_symbol2(PR_SYM_CMD, name, cmdtab, &idx, &hash);
  }

  return (cmdtab ? TRUE : FALSE);
}

unsigned char pr_module_exists(const char *name) {
  return pr_module_get(name) != NULL ? TRUE : FALSE;
}

module *pr_module_get(const char *name) {
  char buf[80] = {'\0'};
  module *m;

  if (name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Check the list of compiled-in modules. */
  for (m = loaded_modules; m; m = m->next) {
    memset(buf, '\0', sizeof(buf));
    pr_snprintf(buf, sizeof(buf), "mod_%s.c", m->name);
    buf[sizeof(buf)-1] = '\0';

    if (strcmp(buf, name) == 0) {
      return m;
    }
  }

  errno = ENOENT;
  return NULL;
}

void modules_list2(int (*listf)(const char *, ...), int flags) {
  if (listf == NULL) {
    listf = printf;
  }

  if (flags & PR_MODULES_LIST_FL_SHOW_STATIC) {
    register unsigned int i = 0;

    listf("Compiled-in modules:\n");
    for (i = 0; static_modules[i]; i++) {
      module *m = static_modules[i];

      if (flags & PR_MODULES_LIST_FL_SHOW_VERSION) {
        const char *version;

        version = m->module_version;
        if (version != NULL) {
          listf("  %s\n", version);

        } else {
          listf("  mod_%s.c\n", m->name);
        }

      } else {
        listf("  mod_%s.c\n", m->name);
      }
    }

  } else {
    module *m;

    listf("Loaded modules:\n");
    for (m = loaded_modules; m; m = m->next) {

      if (flags & PR_MODULES_LIST_FL_SHOW_VERSION) {
        const char *version;

        version = m->module_version;
        if (version != NULL) {
          listf("  %s\n", version);

        } else {  
          listf("  mod_%s.c\n", m->name);
        }

      } else {
        listf("  mod_%s.c\n", m->name);
      }
    }
  }
}

void modules_list(int flags) {
  modules_list2(NULL, flags);
}

int pr_module_load_authtab(module *m) {
  if (m == NULL ||
      m->name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (m->authtable) {
    authtable *authtab;

    for (authtab = m->authtable; authtab->name; authtab++) {
      authtab->m = m;

      if (pr_stash_add_symbol(PR_SYM_AUTH, authtab) < 0) {
        return -1;
      }
    }
  }

  return 0;
}

int pr_module_load_cmdtab(module *m) {
  if (m == NULL ||
      m->name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (m->cmdtable) {
    cmdtable *cmdtab;

    for (cmdtab = m->cmdtable; cmdtab->command; cmdtab++) {
      cmdtab->m = m;

      if (cmdtab->cmd_type == HOOK) {
        if (pr_stash_add_symbol(PR_SYM_HOOK, cmdtab) < 0) {
          return -1;
        }

      } else {
        /* All other cmd_types are for CMDs: PRE_CMD, CMD, POST_CMD, etc. */
        if (pr_stash_add_symbol(PR_SYM_CMD, cmdtab) < 0) {
          return -1;
        }
      }
    }
  }

  return 0;
}

int pr_module_load_conftab(module *m) {
  if (m == NULL ||
      m->name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (m->conftable) {
    conftable *conftab;

    for (conftab = m->conftable; conftab->directive; conftab++) {
      conftab->m = m;

      if (pr_stash_add_symbol(PR_SYM_CONF, conftab) < 0) {
        return -1;
      }
    }
  }

  return 0;
}

int pr_module_load(module *m) {
  char buf[256];

  if (m == NULL ||
      m->name == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Check the API version the module wants to use. */
  if (m->api_version < PR_MODULE_API_VERSION) {
    errno = EACCES;
    return -1;
  }

  /* Do not allow multiple modules with the same name. */
  memset(buf, '\0', sizeof(buf));
  pr_snprintf(buf, sizeof(buf), "mod_%s.c", m->name);
  buf[sizeof(buf)-1] = '\0';

  if (pr_module_get(buf) != NULL) {
    errno = EEXIST;
    return -1;
  }

  /* Invoke the module's initialization routine. */
  if (!m->init ||
      m->init() >= 0) {

    /* Assign a priority to this module. */
    m->priority = curr_module_pri++;

    /* Add the module's config, cmd, and auth tables. */
    if (pr_module_load_conftab(m) < 0) {
      return -1;
    }

    if (pr_module_load_cmdtab(m) < 0) {
      return -1;
    }

    if (pr_module_load_authtab(m) < 0) {
      return -1;
    }

    /* Add the module to the loaded_modules list. */
    if (loaded_modules) {
      m->next = loaded_modules;
      loaded_modules->prev = m;
    }

    loaded_modules = m;

    /* Generate an event. */
    pr_event_generate("core.module-load", buf);
    return 0;
  }

  errno = EPERM;
  return -1;
}

int pr_module_unload(module *m) {
  char buf[256];

  if (m == NULL ||
      m->name == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Make sure this module has been loaded.  We can't unload a module that
   * has not been loaded, now can we?
   */

  memset(buf, '\0', sizeof(buf));
  pr_snprintf(buf, sizeof(buf), "mod_%s.c", m->name);
  buf[sizeof(buf)-1] = '\0';

  if (pr_module_get(buf) == NULL) {
    errno = ENOENT;
    return -1;
  } 

  /* Generate an event. */
  pr_event_generate("core.module-unload", buf);

  /* Remove the module from the loaded_modules list. */
  if (m->prev) {
    m->prev->next = m->next;

  } else {
    /* This module is the start of the loaded_modules list (prev is NULL),
     * so we need to update that pointer, too.
     */
    loaded_modules = m->next;
  }

  if (m->next)
    m->next->prev = m->prev;

  m->prev = m->next = NULL;

  /* Remove the module's config, cmd, and auth tables. */
  if (m->conftable) {
    conftable *conftab;

    for (conftab = m->conftable; conftab->directive; conftab++) {
      pr_stash_remove_symbol(PR_SYM_CONF, conftab->directive, conftab->m);
    }
  }

  if (m->cmdtable) {
    cmdtable *cmdtab;

    for (cmdtab = m->cmdtable; cmdtab->command; cmdtab++) {
      if (cmdtab->cmd_type == HOOK) {
        pr_stash_remove_symbol(PR_SYM_HOOK, cmdtab->command, cmdtab->m);

      } else {
        /* All other cmd_types are for CMDs: PRE_CMD, CMD, POST_CMD, etc. */
        pr_stash_remove_symbol(PR_SYM_CMD, cmdtab->command, cmdtab->m);
      }
    }
  }

  if (m->authtable) {
    authtable *authtab;

    for (authtab = m->authtable; authtab->name; authtab++) {
      pr_stash_remove_symbol(PR_SYM_AUTH, authtab->name, authtab->m);
    }
  }

  /* Remove any callbacks that the module may have registered, i.e.:
   *
   * ctrls
   * events
   * timers
   *
   * Ideally we would also automatically unregister other callbacks that
   * the module may have registered, such as FSIO, NetIO, variables, and
   * response handlers.  However, these APIs do not yet allow for
   * removal of all callbacks for a given module.
   */

#ifdef PR_USE_CTRLS
  pr_ctrls_unregister(m, NULL);
#endif /* PR_USE_CTRLS */
  pr_event_unregister(m, NULL, NULL);
  pr_timer_remove(-1, m);

  return 0;
}

int modules_init(void) {
  register unsigned int i = 0;

  for (i = 0; static_modules[i]; i++) {
    module *m = static_modules[i];

    if (pr_module_load(m) < 0) {
      pr_log_pri(PR_LOG_WARNING, "fatal: unable to load module 'mod_%s.c': %s",
        m->name, strerror(errno));
      exit(1);
    }
  }

  return 0;
}
