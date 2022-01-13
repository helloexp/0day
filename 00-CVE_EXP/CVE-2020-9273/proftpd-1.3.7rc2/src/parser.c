/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2004-2017 The ProFTPD Project team
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
 * distribute the resulting executable, without including the source code
 * for OpenSSL in the source distribution.
 */

/* Configuration parser */

#include "conf.h"
#include "privs.h"

/* Maximum depth of Include patterns/files. */
#define PR_PARSER_INCLUDE_MAX_DEPTH	64

extern xaset_t *server_list;
extern pool *global_config_pool;

static pool *parser_pool = NULL;
static unsigned long parser_include_opts = 0UL;

static array_header *parser_confstack = NULL;
static config_rec **parser_curr_config = NULL;

static array_header *parser_servstack = NULL;
static server_rec **parser_curr_server = NULL;
static unsigned int parser_sid = 1;

static xaset_t **parser_server_list = NULL;

static const char *trace_channel = "config";

struct config_src {
  struct config_src *cs_next;
  pool *cs_pool;
  pr_fh_t *cs_fh;
  unsigned int cs_lineno;
};

static unsigned int parser_curr_lineno = 0;

/* Note: the parser seems to be touchy about this particular value.  If
 * you see strange segfaults occurring in the mergedown() function, it
 * might be because this pool size is too small.
 */
#define PARSER_CONFIG_SRC_POOL_SZ	512

static struct config_src *parser_sources = NULL;

/* Private functions
 */

static struct config_src *add_config_source(pr_fh_t *fh) {
  pool *p = pr_pool_create_sz(parser_pool, PARSER_CONFIG_SRC_POOL_SZ);
  struct config_src *cs = pcalloc(p, sizeof(struct config_src));

  pr_pool_tag(p, "configuration source pool");
  cs->cs_next = NULL;
  cs->cs_pool = p;
  cs->cs_fh = fh;
  cs->cs_lineno = 0;

  if (!parser_sources) {
    parser_sources = cs;

  } else {
    cs->cs_next = parser_sources;
    parser_sources = cs;
  }

  return cs;
}

static char *get_config_word(pool *p, char *word) {
  size_t wordlen;

  /* Should this word be replaced with a value from the environment?
   * If so, tmp will contain the expanded value, otherwise tmp will
   * contain a string duped from the given pool.
   */

  wordlen = strlen(word);

  if (wordlen > 7) {
    char *ptr = NULL;

    /* Does the given word use the environment syntax? We handle this in a
     * while loop in order to handle a) multiple different variables, and b)
     * cases where the substituted value is itself a variable.  Hopefully no
     * one is so clever as to want to actually _use_ the latter approach.
     */
    ptr = strstr(word, "%{env:");
    while (ptr != NULL) {
      char *env, *key, *ptr2, *var;
      unsigned int keylen;

      pr_signals_handle();

      ptr2 = strchr(ptr + 6, '}');
      if (ptr2 == NULL) {
        /* No terminating marker; continue on to the next potential
         * variable in the word.
         */
        ptr2 = ptr + 6;
        ptr = strstr(ptr2, "%{env:");
        continue;
      }

      keylen = (ptr2 - ptr - 6);
      var = pstrndup(p, ptr, (ptr2 - ptr) + 1);

      key = pstrndup(p, ptr + 6, keylen);

      env = pr_env_get(p, key);
      if (env == NULL) {
        /* No value in the environment; continue on to the next potential
         * variable in the word.
         */
        ptr = strstr(ptr2, "%{env:");
        continue;
      }

      word = (char *) sreplace(p, word, var, env, NULL);
      ptr = strstr(word, "%{env:");
    }
  }

  return pstrdup(p, word);
}

static void remove_config_source(void) {
  struct config_src *cs = parser_sources;

  if (cs) {
    parser_sources = cs->cs_next;
    destroy_pool(cs->cs_pool);
  }

  return;
}

/* Public API
 */

int pr_parser_cleanup(void) {
  if (parser_pool) {
    if (parser_servstack->nelts > 1 ||
        (parser_curr_config && *parser_curr_config)) {
      errno = EPERM;
      return -1;
    }

    destroy_pool(parser_pool);
    parser_pool = NULL;
  }

  parser_servstack = NULL;
  parser_curr_server = NULL;

  parser_confstack = NULL;
  parser_curr_config = NULL;

  /* Reset the SID counter. */
  parser_sid = 1;

  return 0;
}

config_rec *pr_parser_config_ctxt_close(int *empty) {
  config_rec *c = *parser_curr_config;

  /* Note that if the current config is empty, it should simply be removed.
   * Such empty configs can happen for <Directory> sections that
   * contain no directives, for example.
   */

  if (parser_curr_config == (config_rec **) parser_confstack->elts) {
    if (c != NULL &&
        (!c->subset || !c->subset->xas_list)) {
      xaset_remove(c->set, (xasetmember_t *) c);
      destroy_pool(c->pool);

      if (empty) {
        *empty = TRUE;
      }
    }

    if (*parser_curr_config) {
      *parser_curr_config = NULL;
    }

    return NULL;
  }

  if (c != NULL &&
      (!c->subset || !c->subset->xas_list)) {
    xaset_remove(c->set, (xasetmember_t *) c);
    destroy_pool(c->pool);

    if (empty) {
      *empty = TRUE;
    }
  }

  parser_curr_config--;
  parser_confstack->nelts--;

  return *parser_curr_config;
}

config_rec *pr_parser_config_ctxt_get(void) {
  if (parser_curr_config) {
    return *parser_curr_config;
  }

  errno = ENOENT;
  return NULL;
}

config_rec *pr_parser_config_ctxt_open(const char *name) {
  config_rec *c = NULL, *parent = *parser_curr_config;
  pool *c_pool = NULL, *parent_pool = NULL;
  xaset_t **set = NULL;

  if (name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (parent) {
    parent_pool = parent->pool;
    set = &parent->subset;

  } else {
    parent_pool = (*parser_curr_server)->pool;
    set = &(*parser_curr_server)->conf;
  }

  /* Allocate a sub-pool for this config_rec.
   *
   * Note: special exception for <Global> configs: the parent pool is
   * 'global_config_pool' (a pool just for that context), not the pool of the
   * parent server.  This keeps <Global> config recs from being freed
   * prematurely, and helps to avoid memory leaks.
   */
  if (strncasecmp(name, "<Global>", 9) == 0) {
    if (global_config_pool == NULL) {
      global_config_pool = make_sub_pool(permanent_pool);
      pr_pool_tag(global_config_pool, "<Global> Pool");
    }

    parent_pool = global_config_pool;
  }

  c_pool = make_sub_pool(parent_pool);
  pr_pool_tag(c_pool, "sub-config pool");

  c = (config_rec *) pcalloc(c_pool, sizeof(config_rec));

  if (!*set) {
    pool *set_pool = make_sub_pool(parent_pool);
    *set = xaset_create(set_pool, NULL);
    (*set)->pool = set_pool;
  }

  xaset_insert(*set, (xasetmember_t *) c);

  c->pool = c_pool;
  c->set = *set;
  c->parent = parent;
  c->name = pstrdup(c->pool, name);

  if (parent) {
    if (parent->config_type == CONF_DYNDIR) {
      c->flags |= CF_DYNAMIC;
    }
  }

  (void) pr_parser_config_ctxt_push(c);
  return c;
}

int pr_parser_config_ctxt_push(config_rec *c) {
  if (c == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (parser_confstack == NULL) {
    errno = EPERM;
    return -1;
  }

  if (!*parser_curr_config) {
    *parser_curr_config = c;

  } else {
    parser_curr_config = (config_rec **) push_array(parser_confstack);
    *parser_curr_config = c;
  }

  return 0;
}

unsigned int pr_parser_get_lineno(void) {
  return parser_curr_lineno;
}

/* Return an array of all supported/known configuration directives. */
static array_header *get_all_directives(pool *p) {
  array_header *names;
  conftable *tab;
  int idx;
  unsigned int hash;

  names = make_array(p, 1, sizeof(const char *));

  idx = -1;
  hash = 0;
  tab = pr_stash_get_symbol2(PR_SYM_CONF, NULL, NULL, &idx, &hash);
  while (idx != -1) {
    pr_signals_handle();

    if (tab != NULL) {
      *((const char **) push_array(names)) = pstrdup(p, tab->directive);

    } else {
      idx++;
    }

    tab = pr_stash_get_symbol2(PR_SYM_CONF, NULL, tab, &idx, &hash);
  }

  return names;
}

int pr_parser_parse_file(pool *p, const char *path, config_rec *start,
    int flags) {
  pr_fh_t *fh;
  struct stat st;
  struct config_src *cs;
  cmd_rec *cmd;
  pool *tmp_pool;
  char *buf, *report_path;
  size_t bufsz;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (parser_servstack == NULL) {
    errno = EPERM;
    return -1;
  }

  tmp_pool = make_sub_pool(p ? p : permanent_pool);
  pr_pool_tag(tmp_pool, "parser file pool");

  report_path = (char *) path;
  if (session.chroot_path) {
    report_path = pdircat(tmp_pool, session.chroot_path, path, NULL);
  }

  if (!(flags & PR_PARSER_FL_DYNAMIC_CONFIG)) {
    pr_trace_msg(trace_channel, 3, "parsing '%s' configuration", report_path);
  }

  fh = pr_fsio_open(path, O_RDONLY);
  if (fh == NULL) {
    int xerrno = errno;

    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  /* Stat the opened file to determine the optimal buffer size for IO. */
  memset(&st, 0, sizeof(st));
  if (pr_fsio_fstat(fh, &st) < 0) {
    int xerrno = errno;

    pr_fsio_close(fh);
    destroy_pool(tmp_pool);

    errno = xerrno;
    return -1;
  }

  if (S_ISDIR(st.st_mode)) {
    pr_fsio_close(fh);
    destroy_pool(tmp_pool);

    errno = EISDIR;
    return -1;
  }

  /* Advise the platform that we will be only reading this file
   * sequentially.
   */
  pr_fs_fadvise(PR_FH_FD(fh), 0, 0, PR_FS_FADVISE_SEQUENTIAL);

  /* Check for world-writable files (and later, files in world-writable
   * directories).
   *
   * For now, just warn about these; later, we will be more draconian.
   */
  if (st.st_mode & S_IWOTH) {
    pr_log_pri(PR_LOG_WARNING, "warning: config file '%s' is world-writable",
     path); 
  }

  fh->fh_iosz = st.st_blksize;

  /* Push the configuration information onto the stack of configuration
   * sources.
   */
  cs = add_config_source(fh);

  if (start != NULL) {
    (void) pr_parser_config_ctxt_push(start);
  }

  bufsz = PR_TUNABLE_PARSER_BUFFER_SIZE;
  buf = pcalloc(tmp_pool, bufsz + 1);

  while (pr_parser_read_line(buf, bufsz) != NULL) {
    pr_signals_handle();

    cmd = pr_parser_parse_line(tmp_pool, buf, 0);
    if (cmd == NULL) {
      continue;
    }

    if (cmd->argc) {
      conftable *conftab;
      char found = FALSE;

      cmd->server = *parser_curr_server;
      cmd->config = *parser_curr_config;

      conftab = pr_stash_get_symbol2(PR_SYM_CONF, cmd->argv[0], NULL,
        &cmd->stash_index, &cmd->stash_hash);
      while (conftab != NULL) {
        modret_t *mr;

        pr_signals_handle();

        cmd->argv[0] = conftab->directive;

        pr_trace_msg(trace_channel, 7,
          "dispatching directive '%s' to module mod_%s", conftab->directive,
          conftab->m->name);

        mr = pr_module_call(conftab->m, conftab->handler, cmd);
        if (mr != NULL) {
          if (MODRET_ISERROR(mr)) {
            if (!(flags & PR_PARSER_FL_DYNAMIC_CONFIG)) {
              pr_log_pri(PR_LOG_WARNING, "fatal: %s on line %u of '%s'",
                MODRET_ERRMSG(mr), cs->cs_lineno, report_path);
              destroy_pool(tmp_pool);
              errno = EPERM;
              return -1;
            }

            pr_log_pri(PR_LOG_WARNING, "warning: %s on line %u of '%s'",
              MODRET_ERRMSG(mr), cs->cs_lineno, report_path);
          }
        }

        if (!MODRET_ISDECLINED(mr)) {
          found = TRUE;
        }

        conftab = pr_stash_get_symbol2(PR_SYM_CONF, cmd->argv[0], conftab,
          &cmd->stash_index, &cmd->stash_hash);
      }

      if (cmd->tmp_pool) {
        destroy_pool(cmd->tmp_pool);
      }

      if (found == FALSE) {
        register unsigned int i;
        char *name;
        size_t namelen;
        int non_ascii = FALSE;

        /* I encountered a case where a particular configuration file had
         * what APPEARED to be a valid directive, but the parser kept reporting
         * that the directive was unknown.  I now suspect that the file in
         * question had embedded UTF8 characters (spaces, perhaps), which
         * would appear as normal spaces in e.g. UTF8-aware editors/terminals,
         * but which the parser would rightly refuse.
         *
         * So to indicate that this might be the case, check for any non-ASCII
         * characters in the "unknown" directive name, and if found, log
         * about them.
         */

        name = cmd->argv[0];
        namelen = strlen(name);

        for (i = 0; i < namelen; i++) {
          if (!isascii((int) name[i])) {
            non_ascii = TRUE;
            break;
          }
        }

        if (!(flags & PR_PARSER_FL_DYNAMIC_CONFIG)) {
          pr_log_pri(PR_LOG_WARNING, "fatal: unknown configuration directive "
            "'%s' on line %u of '%s'", name, cs->cs_lineno, report_path);
          if (non_ascii) {
            pr_log_pri(PR_LOG_WARNING, "fatal: malformed directive name "
              "'%s' (contains non-ASCII characters)", name);

          } else {
            array_header *directives, *similars;

            directives = get_all_directives(tmp_pool);
            similars = pr_str_get_similars(tmp_pool, name, directives, 0,
              PR_STR_FL_IGNORE_CASE);
            if (similars != NULL &&
                similars->nelts > 0) {
              unsigned int nelts;
              const char **names, *msg;

              names = similars->elts;
              nelts = similars->nelts;
              if (nelts > 4) {
                nelts = 4;
              }

              msg = "fatal: Did you mean:";

              if (nelts == 1) {
                msg = pstrcat(tmp_pool, msg, " ", names[0], NULL);

              } else {
                for (i = 0; i < nelts; i++) {
                  msg = pstrcat(tmp_pool, msg, "\n  ", names[i], NULL);
                }
              }

              pr_log_pri(PR_LOG_WARNING, "%s", msg);
            }
          }

          destroy_pool(tmp_pool);
          errno = EPERM;
          return -1;
        }

        pr_log_pri(PR_LOG_WARNING, "warning: unknown configuration directive "
          "'%s' on line %u of '%s'", name, cs->cs_lineno, report_path);
        if (non_ascii) {
          pr_log_pri(PR_LOG_WARNING, "warning: malformed directive name "
            "'%s' (contains non-ASCII characters)", name);
        }
      }
    }

    destroy_pool(cmd->pool);
    memset(buf, '\0', bufsz);
  }

  /* Pop this configuration stream from the stack. */
  remove_config_source();

  pr_fsio_close(fh);

  destroy_pool(tmp_pool);
  return 0;
}

cmd_rec *pr_parser_parse_line(pool *p, const char *text, size_t text_len) {
  register unsigned int i;
  char *arg = "", *ptr, *word = NULL;
  cmd_rec *cmd = NULL;
  pool *sub_pool = NULL;
  array_header *arr = NULL;

  if (p == NULL ||
      text == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (text_len == 0) {
    text_len = strlen(text);
  }

  if (text_len == 0) {
    errno = ENOENT;
    return NULL;
  }

  ptr = (char *) text;

  /* Build a new pool for the command structure and array */
  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "parser cmd subpool");

  cmd = pcalloc(sub_pool, sizeof(cmd_rec));
  cmd->pool = sub_pool;
  cmd->stash_index = -1;
  cmd->stash_hash = 0;

  /* Add each word to the array */
  arr = make_array(cmd->pool, 4, sizeof(char **));
  while ((word = pr_str_get_word(&ptr, 0)) != NULL) {
    char *ptr2;

    pr_signals_handle();
    ptr2 = get_config_word(cmd->pool, word);
    *((char **) push_array(arr)) = ptr2;
    cmd->argc++;
  }

  /* Terminate the array with a NULL. */
  *((char **) push_array(arr)) = NULL;

  /* The array header's job is done, we can forget about it and
   * it will get purged when the command's pool is destroyed.
   */

  cmd->argv = (void **) arr->elts;

  /* Perform a fixup on configuration directives so that:
   *
   *   -argv[0]--  -argv[1]-- ----argv[2]-----
   *   <Option     /etc/adir  /etc/anotherdir>
   *
   *  becomes:
   *
   *   -argv[0]--  -argv[1]-  ----argv[2]----
   *   <Option>    /etc/adir  /etc/anotherdir
   */

  if (cmd->argc &&
      *((char *) cmd->argv[0]) == '<') {
    char *cp;
    size_t cp_len;

    cp = cmd->argv[cmd->argc-1];
    cp_len = strlen(cp);

    if (*(cp + cp_len-1) == '>' &&
        cmd->argc > 1) {

      if (strncmp(cp, ">", 2) == 0) {
        cmd->argv[cmd->argc-1] = NULL;
        cmd->argc--;

      } else {
        *(cp + cp_len-1) = '\0';
      }

      cp = cmd->argv[0];
      cp_len = strlen(cp);
      if (*(cp + cp_len-1) != '>') {
        cmd->argv[0] = pstrcat(cmd->pool, cp, ">", NULL);
      }
    }
  }

  if (cmd->argc < 2) {
    arg = pstrdup(cmd->pool, arg);
  }

  for (i = 1; i < cmd->argc; i++) {
    arg = pstrcat(cmd->pool, arg, *arg ? " " : "", cmd->argv[i], NULL);
  }

  cmd->arg = arg;
  return cmd;
}

int pr_parser_prepare(pool *p, xaset_t **parsed_servers) {

  if (p == NULL) {
    if (parser_pool == NULL) {
      parser_pool = make_sub_pool(permanent_pool);
      pr_pool_tag(parser_pool, "Parser Pool");
    }

    p = parser_pool;
  }

  if (parsed_servers == NULL) {
    parser_server_list = &server_list;

  } else {
    parser_server_list = parsed_servers;
  }

  parser_servstack = make_array(p, 1, sizeof(server_rec *));
  parser_curr_server = (server_rec **) push_array(parser_servstack);
  *parser_curr_server = main_server;

  parser_confstack = make_array(p, 10, sizeof(config_rec *));
  parser_curr_config = (config_rec **) push_array(parser_confstack);
  *parser_curr_config = NULL;

  return 0;
}

/* This functions returns the next line from the configuration stream,
 * skipping commented-out lines and trimming trailing and leading whitespace,
 * returning, in effect, the next line of configuration data on which to
 * act.  This function has the advantage that it can be called by functions
 * that don't have access to configuration file handle, such as the
 * <IfDefine> and <IfModule> configuration handlers.
 */
char *pr_parser_read_line(char *buf, size_t bufsz) {
  struct config_src *cs;

  /* Always use the config stream at the top of the stack. */
  cs = parser_sources;

  if (buf == NULL ||
      cs == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (cs->cs_fh == NULL) {
    errno = EPERM;
    return NULL;
  }

  parser_curr_lineno = cs->cs_lineno;

  /* Check for error conditions. */

  while ((pr_fsio_getline(buf, bufsz, cs->cs_fh, &(cs->cs_lineno))) != NULL) {
    int have_eol = FALSE;
    char *bufp = NULL;
    size_t buflen;

    pr_signals_handle();

    buflen = strlen(buf);
    parser_curr_lineno = cs->cs_lineno;

    /* Trim off the trailing newline, if present. */
    if (buflen &&
        buf[buflen - 1] == '\n') {
      have_eol = TRUE;
      buf[buflen-1] = '\0';
      buflen--;
    }

    if (buflen &&
        buf[buflen - 1] == '\r') {
      buf[buflen-1] = '\0';
      buflen--;
    }

    if (have_eol == FALSE) {
      pr_log_pri(PR_LOG_WARNING,
        "warning: handling possibly truncated configuration data at "
        "line %u of '%s'", cs->cs_lineno, cs->cs_fh->fh_path);
    }

    /* Advance past any leading whitespace. */
    for (bufp = buf; *bufp && PR_ISSPACE(*bufp); bufp++);

    /* Check for commented or blank lines at this point, and just continue on
     * to the next configuration line if found.  If not, return the
     * configuration line.
     */
    if (*bufp == '#' || !*bufp) {
      continue;

    } else {

      /* Copy the value of bufp back into the pointer passed in
       * and return it.
       */
      buf = bufp;

      return buf;
    }
  }

  return NULL;
}

server_rec *pr_parser_server_ctxt_close(void) {
  if (!parser_curr_server) {
    errno = ENOENT;
    return NULL;
  }

  /* Disallow underflows. */
  if (parser_curr_server == (server_rec **) parser_servstack->elts) {
    errno = EPERM;
    return NULL;
  }

  parser_curr_server--;
  parser_servstack->nelts--;

  return *parser_curr_server;
}

server_rec *pr_parser_server_ctxt_get(void) {
  if (parser_curr_server) {
    return *parser_curr_server;
  }

  errno = ENOENT;
  return NULL;
}

int pr_parser_server_ctxt_push(server_rec *s) {
  if (s == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (parser_servstack == NULL) {
    errno = EPERM;
    return -1;
  }

  parser_curr_server = (server_rec **) push_array(parser_servstack);
  *parser_curr_server = s;

  return 0;
}

server_rec *pr_parser_server_ctxt_open(const char *addrstr) {
  server_rec *s;
  pool *p;

  p = make_sub_pool(permanent_pool);
  pr_pool_tag(p, "<VirtualHost> Pool");

  s = (server_rec *) pcalloc(p, sizeof(server_rec));
  s->pool = p;
  s->config_type = CONF_VIRTUAL;
  s->sid = ++parser_sid;
  s->notes = pr_table_nalloc(p, 0, 8);

  /* TCP KeepAlive is enabled by default, with the system defaults. */
  s->tcp_keepalive = palloc(s->pool, sizeof(struct tcp_keepalive));
  s->tcp_keepalive->keepalive_enabled = TRUE;
  s->tcp_keepalive->keepalive_idle = -1;
  s->tcp_keepalive->keepalive_count = -1;
  s->tcp_keepalive->keepalive_intvl = -1;

  /* Have to make sure it ends up on the end of the chain, otherwise
   * main_server becomes useless.
   */
  xaset_insert_end(*parser_server_list, (xasetmember_t *) s);
  s->set = *parser_server_list;
  if (addrstr) {
    s->ServerAddress = pstrdup(s->pool, addrstr);
  }

  /* Default server port */
  s->ServerPort = pr_inet_getservport(s->pool, "ftp", "tcp");

  (void) pr_parser_server_ctxt_push(s);
  return s;
}

unsigned long pr_parser_set_include_opts(unsigned long opts) {
  unsigned long prev_opts;

  prev_opts = parser_include_opts;
  parser_include_opts = opts;

  return prev_opts;
}

static const char *tmpfile_patterns[] = {
  "*~",
  "*.sw?",
  NULL
};

static int is_tmp_file(const char *file) {
  register unsigned int i;

  for (i = 0; tmpfile_patterns[i]; i++) {
    if (pr_fnmatch(tmpfile_patterns[i], file, PR_FNM_PERIOD) == 0) {
      return TRUE;
    }
  }

  return FALSE;
}

static int config_filename_cmp(const void *a, const void *b) {
  return strcmp(*((char **) a), *((char **) b));
}

static int parse_wildcard_config_path(pool *p, const char *path,
    unsigned int depth) {
  register unsigned int i;
  int res, xerrno;
  pool *tmp_pool;
  array_header *globbed_dirs = NULL;
  const char *component = NULL, *parent_path = NULL, *suffix_path = NULL;
  struct stat st;
  size_t path_len, component_len;
  char *name_pattern = NULL;
  void *dirh = NULL;
  struct dirent *dent = NULL;

  if (depth > PR_PARSER_INCLUDE_MAX_DEPTH) {
    pr_log_pri(PR_LOG_WARNING, "error: resolving wildcard pattern in '%s' "
      "exceeded maximum filesystem depth (%u)", path,
      (unsigned int) PR_PARSER_INCLUDE_MAX_DEPTH);
    errno = EINVAL;
    return -1;
  }

  path_len = strlen(path);
  if (path_len < 2) {
    pr_trace_msg(trace_channel, 7, "path '%s' too short to be wildcard path",
      path);

    /* The first character must be a slash, and we need at least one more
     * character in the path as a glob character.
     */
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Include sub-pool");

  /* We need to find the first component of the path which contains glob
   * characters.  We then use the path up to the previous component as the
   * parent directory to open, and the glob-bearing component as the filter
   * for directories within the parent.
   */

  component = path + 1;
  while (TRUE) {
    int last_component = FALSE;
    char *ptr;

    pr_signals_handle();

    ptr = strchr(component, '/');
    if (ptr != NULL) {
      component_len = ptr - component;

    } else {
      component_len = strlen(component);
      last_component = TRUE;
    }

    if (memchr(component, (int) '*', component_len) != NULL ||
        memchr(component, (int) '?', component_len) != NULL ||
        memchr(component, (int) '[', component_len) != NULL) {

      name_pattern = pstrndup(tmp_pool, component, component_len);

      if (parent_path == NULL) {
        parent_path = pstrndup(tmp_pool, "/", 1);
      }

      if (ptr != NULL) {
        suffix_path = pstrdup(tmp_pool, ptr + 1);
      }

      break;
    }

    if (parent_path != NULL) {
      parent_path = pdircat(tmp_pool, parent_path,
        pstrndup(tmp_pool, component, component_len), NULL);

    } else {
      parent_path = pstrndup(tmp_pool, "/", 1);
    }

    if (last_component) {
      break;
    }

    component = ptr + 1;
  }

  if (name_pattern == NULL) {
    pr_trace_msg(trace_channel, 4,
      "unable to process invalid, non-globbed path '%s'", path);
    errno = ENOENT;
    return -1;
  }

  pr_fs_clear_cache2(parent_path);
  if (pr_fsio_lstat(parent_path, &st) < 0) {
    xerrno = errno;

    pr_log_pri(PR_LOG_WARNING,
      "error: failed to check configuration path '%s': %s", parent_path,
      strerror(xerrno));

    destroy_pool(tmp_pool);
    errno = xerrno;
    return -1;
  }

  if (S_ISLNK(st.st_mode) &&
      !(parser_include_opts & PR_PARSER_INCLUDE_OPT_ALLOW_SYMLINKS)) {
    pr_log_pri(PR_LOG_WARNING,
      "error: cannot read configuration path '%s': Symbolic link", parent_path);
    destroy_pool(tmp_pool);
    errno = ENOTDIR;
    return -1;
  }

  pr_log_pri(PR_LOG_DEBUG,
    "processing configuration directory '%s' using pattern '%s', suffix '%s'",
    parent_path, name_pattern, suffix_path);

  dirh = pr_fsio_opendir(parent_path);
  if (dirh == NULL) {
    pr_log_pri(PR_LOG_WARNING,
      "error: unable to open configuration directory '%s': %s", parent_path,
      strerror(errno));
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  globbed_dirs = make_array(tmp_pool, 0, sizeof(char *));

  while ((dent = pr_fsio_readdir(dirh)) != NULL) {
    pr_signals_handle();

    if (strncmp(dent->d_name, ".", 2) == 0 ||
        strncmp(dent->d_name, "..", 3) == 0) {
      continue;
    }

    if (parser_include_opts & PR_PARSER_INCLUDE_OPT_IGNORE_TMP_FILES) {
      if (is_tmp_file(dent->d_name) == TRUE) {
        pr_trace_msg(trace_channel, 19,
          "ignoring temporary file '%s' found in directory '%s'", dent->d_name,
          parent_path);
        continue;
      }
    }

    if (pr_fnmatch(name_pattern, dent->d_name, PR_FNM_PERIOD) == 0) {
      pr_trace_msg(trace_channel, 17,
        "matched '%s' path with wildcard pattern '%s'", dent->d_name,
        name_pattern);

      *((char **) push_array(globbed_dirs)) = pdircat(tmp_pool, parent_path,
        dent->d_name, suffix_path, NULL);
    }
  }

  pr_fsio_closedir(dirh);

  if (globbed_dirs->nelts == 0) {
    pr_log_pri(PR_LOG_WARNING,
      "error: no matches found for wildcard directory '%s'", path);
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return -1;
  }

  depth++;

  qsort((void *) globbed_dirs->elts, globbed_dirs->nelts, sizeof(char *),
    config_filename_cmp);

  for (i = 0; i < globbed_dirs->nelts; i++) {
    const char *globbed_dir;

    globbed_dir = ((const char **) globbed_dirs->elts)[i];
    res = parse_config_path2(p, globbed_dir, depth);
    if (res < 0) {
      xerrno = errno;

      pr_trace_msg(trace_channel, 7, "error parsing wildcard path '%s': %s",
        globbed_dir, strerror(xerrno));

      destroy_pool(tmp_pool);
      errno = xerrno;
      return -1;
    }
  }

  destroy_pool(tmp_pool);
  return 0;
}

int parse_config_path2(pool *p, const char *path, unsigned int depth) {
  struct stat st;
  int have_glob;
  void *dirh;
  struct dirent *dent;
  array_header *file_list;
  char *dup_path, *ptr;
  pool *tmp_pool;

  if (p == NULL ||
      path == NULL ||
      (depth > PR_PARSER_INCLUDE_MAX_DEPTH)) {
    errno = EINVAL;
    return -1;
  }

  if (pr_fs_valid_path(path) < 0) {
    errno = EINVAL;
    return -1;
  }

  have_glob = pr_str_is_fnmatch(path);
  if (have_glob) {
    /* Even though the path may be valid, it also may not be a filesystem
     * path; consider custom FSIO modules.  Thus if the path does not start
     * with a slash, it should not be treated as having globs.
     */
    if (*path != '/') {
      have_glob = FALSE;
    }
  }

  pr_fs_clear_cache2(path);

  if (have_glob) {
    pr_trace_msg(trace_channel, 19, "parsing '%s' as a globbed path", path);
  }

  if (!have_glob &&
      pr_fsio_lstat(path, &st) < 0) {
    return -1;
  }

  /* If path is not a glob pattern, and is a symlink OR is not a directory,
   * then use the normal parsing function for the file.
   */
  if (have_glob == FALSE &&
      (S_ISLNK(st.st_mode) ||
       !S_ISDIR(st.st_mode))) {
    int res, xerrno;

    PRIVS_ROOT
    res = pr_parser_parse_file(p, path, NULL, 0);
    xerrno = errno;
    PRIVS_RELINQUISH

    errno = xerrno;
    return res;
  }

  tmp_pool = make_sub_pool(p);
  pr_pool_tag(tmp_pool, "Include sub-pool");

  /* Handle the glob/directory. */
  dup_path = pstrdup(tmp_pool, path);

  ptr = strrchr(dup_path, '/');

  if (have_glob) {
    int have_glob_dir;

    /* Note that we know, by definition, that ptr CANNOT be null here; dup_path
     * is a duplicate of path, and the first character (if nothing else) of
     * path MUST be a slash, per earlier checks.
     */
    *ptr = '\0';

    /* We just changed ptr, thus we DO need to check whether the now-modified
     * path contains fnmatch(3) characters again.
     */
    have_glob_dir = pr_str_is_fnmatch(dup_path);
    if (have_glob_dir) {
      const char *glob_dir;

      if (parser_include_opts & PR_PARSER_INCLUDE_OPT_IGNORE_WILDCARDS) {
        pr_log_pri(PR_LOG_WARNING, "error: wildcard patterns not allowed in "
          "configuration directory name '%s'", dup_path);
        destroy_pool(tmp_pool);
        errno = EINVAL;
        return -1;
      }

      *ptr = '/';
      glob_dir = pstrdup(p, dup_path);
      destroy_pool(tmp_pool);

      return parse_wildcard_config_path(p, glob_dir, depth);
    }

    ptr++;

    /* Check the directory component. */
    pr_fs_clear_cache2(dup_path);
    if (pr_fsio_lstat(dup_path, &st) < 0) {
      int xerrno = errno;

      pr_log_pri(PR_LOG_WARNING,
        "error: failed to check configuration path '%s': %s", dup_path,
        strerror(xerrno));

      destroy_pool(tmp_pool);
      errno = xerrno;
      return -1;
    }

    if (S_ISLNK(st.st_mode) &&
        !(parser_include_opts & PR_PARSER_INCLUDE_OPT_ALLOW_SYMLINKS)) {
      pr_log_pri(PR_LOG_WARNING,
        "error: cannot read configuration path '%s': Symbolic link", path);
      destroy_pool(tmp_pool);
      errno = ENOTDIR;
      return -1;
    }

    if (have_glob_dir == FALSE &&
        pr_str_is_fnmatch(ptr) == FALSE) {
      pr_log_pri(PR_LOG_WARNING,
        "error: wildcard pattern required for file '%s'", ptr);
      destroy_pool(tmp_pool);
      errno = EINVAL;
      return -1;
    }
  }

  pr_trace_msg(trace_channel, 3, "processing configuration directory '%s'", dup_path);

  dirh = pr_fsio_opendir(dup_path);
  if (dirh == NULL) {
    pr_log_pri(PR_LOG_WARNING,
      "error: unable to open configuration directory '%s': %s", dup_path,
      strerror(errno));
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return -1;
  }

  file_list = make_array(tmp_pool, 0, sizeof(char *));

  while ((dent = pr_fsio_readdir(dirh)) != NULL) {
    pr_signals_handle();

    if (strncmp(dent->d_name, ".", 2) == 0 ||
        strncmp(dent->d_name, "..", 3) == 0) {
      continue;
    }

    if (parser_include_opts & PR_PARSER_INCLUDE_OPT_IGNORE_TMP_FILES) {
      if (is_tmp_file(dent->d_name) == TRUE) {
        pr_trace_msg(trace_channel, 19,
          "ignoring temporary file '%s' found in directory '%s'", dent->d_name,
          dup_path);
        continue;
      }
    }

    if (have_glob == FALSE ||
        (ptr != NULL &&
         pr_fnmatch(ptr, dent->d_name, PR_FNM_PERIOD) == 0)) {
      *((char **) push_array(file_list)) = pdircat(tmp_pool, dup_path,
        dent->d_name, NULL);
    }
  }

  pr_fsio_closedir(dirh);

  if (file_list->nelts) {
    register unsigned int i;

    qsort((void *) file_list->elts, file_list->nelts, sizeof(char *),
      config_filename_cmp);

    for (i = 0; i < file_list->nelts; i++) {
      int res, xerrno;
      char *file;

      file = ((char **) file_list->elts)[i];

      /* Make sure we always parse the files with root privs.  The
       * previously parsed file might have had root privs relinquished
       * (e.g. by its directive handlers), but when we first start up,
       * we have root privs.  See Bug#3855.
       */
      PRIVS_ROOT
      res = pr_parser_parse_file(tmp_pool, file, NULL, 0);
      xerrno = errno;
      PRIVS_RELINQUISH

      if (res < 0) {
        pr_log_pri(PR_LOG_WARNING,
          "error: unable to open parse file '%s': %s", file,
          strerror(xerrno));
      }
    }
  }

  destroy_pool(tmp_pool);
  return 0;
}

int parse_config_path(pool *p, const char *path) {
  return parse_config_path2(p, path, 0);
}
