/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2009-2017 The ProFTPD Project team
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

#include "conf.h"

/* This struct and the list of such structs are used to try to reduce
 * the use of the following idiom to identify which command a given
 * cmd_rec is:
 *
 *  if (strcmp(cmd->argv[0], C_USER) == 0) 
 *
 * Rather than using strcmp(3) so freely, try to reduce the command to
 * a fixed ID (an index into the struct list); this ID can then be compared
 * rather than using strcmp(3).  For commands not in the list, strcmp(3)
 * can always be used as a fallback.
 *
 * A future improvement would be to sort the entries in the table so that
 * the most common commands appear earlier in the table, and make the
 * linear scan even shorter.  But I'd need to collect better metrics in
 * order to do that.
 */

struct cmd_entry {
  const char *cmd_name;
  size_t cmd_namelen;
};

static struct cmd_entry cmd_ids[] = {
  { " ",	1 },	/* Index 0 is intentionally filled with a sentinel */
  { C_USER,	4 },	/* PR_CMD_USER_ID (1) */
  { C_PASS,	4 },	/* PR_CMD_PASS_ID (2) */
  { C_ACCT,	4 },	/* PR_CMD_ACCT_ID (3) */
  { C_CWD,	3 },	/* PR_CMD_CWD_ID (4) */
  { C_XCWD,	4 },	/* PR_CMD_XCWD_ID (5) */
  { C_CDUP,	4 },	/* PR_CMD_CDUP_ID (6) */
  { C_XCUP,	4 },	/* PR_CMD_XCUP_ID (7) */
  { C_SMNT,	4 },	/* PR_CMD_SMNT_ID (8) */
  { C_REIN,	4 },	/* PR_CMD_REIN_ID (9) */
  { C_QUIT,	4 },	/* PR_CMD_QUIT_ID (10) */
  { C_PORT,	4 },	/* PR_CMD_PORT_ID (11) */
  { C_EPRT,	4 },	/* PR_CMD_EPRT_ID (12) */
  { C_PASV,	4 },	/* PR_CMD_PASV_ID (13) */
  { C_EPSV,	4 },	/* PR_CMD_EPSV_ID (14) */ 
  { C_TYPE,	4 },	/* PR_CMD_TYPE_ID (15) */
  { C_STRU,	4 },	/* PR_CMD_STRU_ID (16) */
  { C_MODE,	4 },	/* PR_CMD_MODE_ID (17) */
  { C_RETR,	4 },	/* PR_CMD_RETR_ID (18) */
  { C_STOR,	4 },	/* PR_CMD_STOR_ID (19) */
  { C_STOU,	4 },	/* PR_CMD_STOU_ID (20) */
  { C_APPE,	4 },	/* PR_CMD_APPE_ID (21) */
  { C_ALLO,	4 },	/* PR_CMD_ALLO_ID (22) */
  { C_REST,	4 },	/* PR_CMD_REST_ID (23) */
  { C_RNFR,	4 },	/* PR_CMD_RNFR_ID (24) */
  { C_RNTO,	4 },	/* PR_CMD_RNTO_ID (25) */
  { C_ABOR,	4 },	/* PR_CMD_ABOR_ID (26) */
  { C_DELE,	4 },	/* PR_CMD_DELE_ID (27) */
  { C_MDTM,	4 },	/* PR_CMD_MDTM_ID (28) */
  { C_RMD,	3 },	/* PR_CMD_RMD_ID (29) */
  { C_XRMD,	4 },	/* PR_CMD_XRMD_ID (30) */
  { C_MKD,	3 },	/* PR_CMD_MKD_ID (31) */
  { C_MLSD,	4 },	/* PR_CMD_MLSD_ID (32) */
  { C_MLST,	4 },	/* PR_CMD_MLST_ID (33) */
  { C_XMKD,	4 },	/* PR_CMD_XMKD_ID (34) */
  { C_PWD,	3 },	/* PR_CMD_PWD_ID (35) */
  { C_XPWD,	4 },	/* PR_CMD_XPWD_ID (36) */
  { C_SIZE,	4 },	/* PR_CMD_SIZE_ID (37) */
  { C_LIST,	4 },	/* PR_CMD_LIST_ID (38) */
  { C_NLST,	4 },	/* PR_CMD_NLST_ID (39) */
  { C_SITE,	4 },	/* PR_CMD_SITE_ID (40) */
  { C_SYST,	4 },	/* PR_CMD_SYST_ID (41) */
  { C_STAT,	4 },	/* PR_CMD_STAT_ID (42) */
  { C_HELP,	4 },	/* PR_CMD_HELP_ID (43) */
  { C_NOOP,	4 },	/* PR_CMD_NOOP_ID (44) */
  { C_FEAT,	4 },	/* PR_CMD_FEAT_ID (45) */
  { C_OPTS,	4 },	/* PR_CMD_OPTS_ID (46) */
  { C_LANG,	4 },	/* PR_CMD_LANG_ID (47) */
  { C_ADAT,	4 },	/* PR_CMD_ADAT_ID (48) */
  { C_AUTH,	4 },	/* PR_CMD_AUTH_ID (49) */
  { C_CCC,	3 },	/* PR_CMD_CCC_ID (50) */
  { C_CONF,	4 },	/* PR_CMD_CONF_ID (51) */
  { C_ENC,	3 },	/* PR_CMD_ENC_ID (52) */
  { C_MIC,	3 },	/* PR_CMD_MIC_ID (53) */
  { C_PBSZ,	4 },	/* PR_CMD_PBSZ_ID (54) */
  { C_PROT,	4 },	/* PR_CMD_PROT_ID (55) */
  { C_MFF,	3 },	/* PR_CMD_MFF_ID (56) */
  { C_MFMT,	4 },	/* PR_CMD_MFMT_ID (57) */
  { C_HOST,	4 },	/* PR_CMD_HOST_ID (58) */
  { C_CLNT,	4 },	/* PR_CMD_CLNT_ID (59) */
  { C_RANG,	4 },	/* PR_CMD_RANG_ID (60) */

  { NULL,	0 }
};

/* Due to potential XSS issues (see Bug#4143), we want to explicitly
 * check for commands from other text-based protocols (e.g. HTTP and SMTP);
 * if we see these, we want to close the connection with extreme prejudice.
 */

static struct cmd_entry http_ids[] = {
  { " ",	1 },    /* Index 0 is intentionally filled with a sentinel */
  { "CONNECT",	7 },
  { "DELETE",	6 },
  { "GET",	3 },
  { "HEAD",	4 },
  { "OPTIONS",	7 },
  { "PATCH",	5 },
  { "POST",	4 },
  { "PUT",	3 },

  { NULL,	0 }
};

static struct cmd_entry smtp_ids[] = {
  { " ",	1 },    /* Index 0 is intentionally filled with a sentinel */
  { "DATA",	4 },
  { "EHLO",	4 },
  { "HELO",	4 },
  { "MAIL",	4 },
  { "RCPT",	4 },
  { "RSET",	4 },
  { "VRFY",	4 },

  { NULL,	0 }
};

static const char *trace_channel = "command";

cmd_rec *pr_cmd_alloc(pool *p, unsigned int argc, ...) {
  pool *newpool = NULL;
  cmd_rec *cmd = NULL;
  int *xerrno = NULL;
  va_list args;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }
 
  newpool = make_sub_pool(p); 
  pr_pool_tag(newpool, "cmd_rec pool");
 
  cmd = pcalloc(newpool, sizeof(cmd_rec));
  cmd->argc = argc;
  cmd->stash_index = -1;
  cmd->stash_hash = 0;
  cmd->pool = newpool;
  cmd->tmp_pool = make_sub_pool(cmd->pool);
  pr_pool_tag(cmd->tmp_pool, "cmd_rec tmp pool");

  if (argc > 0) {
    register unsigned int i = 0;

    cmd->argv = pcalloc(cmd->pool, sizeof(void *) * (argc + 1));
    va_start(args, argc);

    for (i = 0; i < argc; i++) {
      cmd->argv[i] = va_arg(args, void *);
    }

    va_end(args);
    cmd->argv[argc] = NULL;
  }

  /* This table will not contain that many entries, so a low number
   * of chains should suffice.
   */
  cmd->notes = pr_table_nalloc(cmd->pool, 0, 8);

  /* Initialize the "errno" note to be zero, so that it is always present. */
  xerrno = palloc(cmd->pool, sizeof(int));
  *xerrno = 0;
  (void) pr_table_add(cmd->notes, "errno", xerrno, sizeof(int));

  return cmd;
}

int pr_cmd_clear_cache(cmd_rec *cmd) {
  if (cmd == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Clear the strings that have been cached for this command in the
   * notes table.
   */

  (void) pr_table_remove(cmd->notes, "displayable-str", NULL);
  (void) pr_cmd_set_errno(cmd, 0);

  return 0;
}

int pr_cmd_cmp(cmd_rec *cmd, int cmd_id) {
  if (cmd == NULL ||
      cmd_id <= 0) {
    errno = EINVAL;
    return -1;
  }

  if (cmd->argc == 0 ||
      cmd->argv == NULL) {
    return 1;
  }

  /* The cmd ID is unknown; look it up. */
  if (cmd->cmd_id == 0) {
    cmd->cmd_id = pr_cmd_get_id(cmd->argv[0]);
  }

  /* The cmd ID is known to be unknown. */
  if (cmd->cmd_id < 0) {
    return 1;
  }

  if (cmd->cmd_id == cmd_id) {
    return 0;
  }

  return cmd->cmd_id < cmd_id ? -1 : 1;
}

int pr_cmd_get_errno(cmd_rec *cmd) {
  void *v;
  int *xerrno;

  if (cmd == NULL) {
    errno = EINVAL;
    return -1;
  }

  v = (void *) pr_table_get(cmd->notes, "errno", NULL);
  if (v == NULL) {
    errno = ENOENT;
    return -1;
  }

  xerrno = v;
  return *xerrno;
}

int pr_cmd_set_errno(cmd_rec *cmd, int xerrno) {
  void *v;

  if (cmd == NULL ||
      cmd->notes == NULL) {
    errno = EINVAL;
    return -1;
  }

  v = (void *) pr_table_get(cmd->notes, "errno", NULL);
  if (v == NULL) {
    errno = ENOENT;
    return -1;
  }

  *((int *) v) = xerrno;
  return 0;
}

int pr_cmd_set_name(cmd_rec *cmd, const char *cmd_name) {
  if (cmd == NULL ||
      cmd_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  cmd->argv[0] = (char *) cmd_name;
  cmd->cmd_id = pr_cmd_get_id(cmd->argv[0]);

  return 0;
}

int pr_cmd_strcmp(cmd_rec *cmd, const char *cmd_name) {
  int cmd_id, res;
  size_t cmd_namelen;

  if (cmd == NULL ||
      cmd_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (cmd->argc == 0 ||
      cmd->argv == NULL) {
    return 1;
  }

  /* The cmd ID is unknown; look it up. */
  if (cmd->cmd_id == 0) {
    cmd->cmd_id = pr_cmd_get_id(cmd->argv[0]);
  }

  if (cmd->cmd_id > 0) {
    cmd_id = pr_cmd_get_id(cmd_name); 

    res = pr_cmd_cmp(cmd, cmd_id);
    if (res == 0) {
      return 0;
    }

    return strncmp(cmd_name, cmd->argv[0],
      cmd_ids[cmd->cmd_id].cmd_namelen + 1);
  }

  cmd_namelen = strlen(cmd_name);
  return strncmp(cmd->argv[0], cmd_name, cmd_namelen + 1);
}

const char *pr_cmd_get_displayable_str(cmd_rec *cmd, size_t *str_len) {
  const char *res;
  unsigned int argc;
  void **argv;
  pool *p;

  if (cmd == NULL) {
    errno = EINVAL;
    return NULL;
  }

  res = pr_table_get(cmd->notes, "displayable-str", NULL);
  if (res != NULL) {
    if (str_len != NULL) {
      *str_len = strlen(res);
    }

    return res;
  }

  argc = cmd->argc;
  argv = cmd->argv;
  p = cmd->pool;

  res = "";

  /* Check for "sensitive" commands. */
  if (pr_cmd_cmp(cmd, PR_CMD_PASS_ID) == 0 ||
      pr_cmd_cmp(cmd, PR_CMD_ADAT_ID) == 0) {
    argc = 2;
    argv[1] = "(hidden)";
  }

  if (argc > 0) {
    register unsigned int i;

    res = pstrcat(p, res, pr_fs_decode_path(p, argv[0]), NULL);

    for (i = 1; i < argc; i++) {
      res = pstrcat(p, res, " ", pr_fs_decode_path(p, argv[i]), NULL);
    }
  }

  if (pr_table_add(cmd->notes, pstrdup(cmd->pool, "displayable-str"),
      pstrdup(cmd->pool, res), 0) < 0) {
    if (errno != EEXIST) {
      pr_trace_msg(trace_channel, 4,
        "error setting 'displayable-str' command note: %s", strerror(errno));
    }
  }

  if (str_len != NULL) {
    *str_len = strlen(res);
  }

  return res;
}

int pr_cmd_get_id(const char *cmd_name) {
  register unsigned int i;
  size_t cmd_namelen;

  if (cmd_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  cmd_namelen = strlen(cmd_name);

  /* Take advantage of the fact that we know, a priori, that the shortest
   * command name in the list is 3 characters, and that the longest is 4
   * characters.  No need to scan the list if we know that the given name
   * is not within that length range.
   */
  if (cmd_namelen < PR_CMD_MIN_NAMELEN ||
      cmd_namelen > PR_CMD_MAX_NAMELEN) {
    errno = ENOENT;
    return -1;
  }

  for (i = 1; cmd_ids[i].cmd_name != NULL; i++) {
    if (cmd_ids[i].cmd_namelen != cmd_namelen) {
      continue;
    }

    if (cmd_ids[i].cmd_name[0] != cmd_name[0]) {
      continue;
    }

    if (strcmp(cmd_ids[i].cmd_name, cmd_name) == 0) {
      return i;
    }
  }

  errno = ENOENT;
  return -1;
}

static int is_known_cmd(struct cmd_entry *known_cmds, const char *cmd_name,
    size_t cmd_namelen) {
  register unsigned int i;
  int known = FALSE;

  for (i = 0; known_cmds[i].cmd_name != NULL; i++) {
    if (cmd_namelen == known_cmds[i].cmd_namelen) {
      if (strncmp(cmd_name, known_cmds[i].cmd_name, cmd_namelen + 1) == 0) {
        known = TRUE;
        break;
      }
    }
  }

  return known;
}

int pr_cmd_is_http(cmd_rec *cmd) {
  const char *cmd_name;
  size_t cmd_namelen;

  if (cmd == NULL) {
    errno = EINVAL;
    return -1;
  }

  cmd_name = cmd->argv[0];
  if (cmd_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (cmd->cmd_id == 0) {
    cmd->cmd_id = pr_cmd_get_id(cmd_name);
  }

  if (cmd->cmd_id >= 0) {
    return FALSE;
  }

  cmd_namelen = strlen(cmd_name);
  return is_known_cmd(http_ids, cmd_name, cmd_namelen);
}

int pr_cmd_is_smtp(cmd_rec *cmd) {
  const char *cmd_name;
  size_t cmd_namelen;

  if (cmd == NULL) {
    errno = EINVAL;
    return -1;
  }

  cmd_name = cmd->argv[0];
  if (cmd_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (cmd->cmd_id == 0) {
    cmd->cmd_id = pr_cmd_get_id(cmd_name);
  }

  if (cmd->cmd_id >= 0) {
    return FALSE;
  }

  cmd_namelen = strlen(cmd_name);
  return is_known_cmd(smtp_ids, cmd_name, cmd_namelen);
}

int pr_cmd_is_ssh2(cmd_rec *cmd) {
  const char *cmd_name;

  if (cmd == NULL) {
    errno = EINVAL;
    return -1;
  }

  cmd_name = cmd->argv[0];
  if (cmd_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (cmd->cmd_id == 0) {
    cmd->cmd_id = pr_cmd_get_id(cmd_name);
  }

  if (cmd->cmd_id >= 0) {
    return FALSE;
  }

  if (strncmp(cmd_name, "SSH-2.0-", 8) == 0 ||
      strncmp(cmd_name, "SSH-1.99-", 9) == 0) {
    return TRUE;
  }

  return FALSE;
}
