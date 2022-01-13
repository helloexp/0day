/*
 * ProFTPD - mod_sftp interoperability
 * Copyright (c) 2008-2016 TJ Saunders
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

#include "mod_sftp.h"
#include "ssh2.h"
#include "channel.h"
#include "disconnect.h"
#include "interop.h"
#include "fxp.h"

extern module sftp_module;

/* By default, each client is assumed to support all of the features in
 * which we are interested.
 */
static unsigned int default_flags =
  SFTP_SSH2_FEAT_IGNORE_MSG |
  SFTP_SSH2_FEAT_MAC_LEN |
  SFTP_SSH2_FEAT_CIPHER_USE_K |
  SFTP_SSH2_FEAT_REKEYING |
  SFTP_SSH2_FEAT_USERAUTH_BANNER |
  SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO |
  SFTP_SSH2_FEAT_SERVICE_IN_HOST_SIG |
  SFTP_SSH2_FEAT_SERVICE_IN_PUBKEY_SIG |
  SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG |
  SFTP_SSH2_FEAT_NO_DATA_WHILE_REKEYING;

struct sftp_version_pattern {
  const char *pattern;
  int disabled_flags;
  pr_regex_t *pre;
};

static struct sftp_version_pattern known_versions[] = {

  { "^OpenSSH-2\\.0.*|"
    "^OpenSSH-2\\.1.*|"
    "^OpenSSH_2\\.1.*|"
    "^OpenSSH_2\\.2.*|"
    "^OpenSSH_2\\.3\\.0.*",	SFTP_SSH2_FEAT_USERAUTH_BANNER|
				SFTP_SSH2_FEAT_REKEYING,		NULL },

  { "^OpenSSH_2\\.3\\..*|"
    "^OpenSSH_2\\.5\\.0p1.*|"
    "^OpenSSH_2\\.5\\.1p1.*|"
    "^OpenSSH_2\\.5\\.0.*|"
    "^OpenSSH_2\\.5\\.1.*|"
    "^OpenSSH_2\\.5\\.2.*|"
    "^OpenSSH_2\\.5\\.3.*",	SFTP_SSH2_FEAT_REKEYING,		NULL },

  { "^OpenSSH.*",		0,					NULL },

  { ".*J2SSH_Maverick.*",	SFTP_SSH2_FEAT_REKEYING,		NULL },

  { ".*MindTerm.*",		0,					NULL },

  { "^Sun_SSH_1\\.0.*",		SFTP_SSH2_FEAT_REKEYING,		NULL },

  { "^2\\.1\\.0.*|"
    "^2\\.1 .*",		SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG|
				SFTP_SSH2_FEAT_SERVICE_IN_HOST_SIG|
				SFTP_SSH2_FEAT_MAC_LEN,			NULL },

  { "^2\\.0\\.13.*|"
    "^2\\.0\\.14.*|"
    "^2\\.0\\.15.*|"
    "^2\\.0\\.16.*|"
    "^2\\.0\\.17.*|"
    "^2\\.0\\.18.*|"
    "^2\\.0\\.19.*",		SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG|
				SFTP_SSH2_FEAT_SERVICE_IN_HOST_SIG|
				SFTP_SSH2_FEAT_SERVICE_IN_PUBKEY_SIG|
				SFTP_SSH2_FEAT_MAC_LEN,			NULL },

  { "^2\\.0\\.11.*|"
    "^2\\.0\\.12.*",		SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG|
				SFTP_SSH2_FEAT_SERVICE_IN_PUBKEY_SIG|
    				SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO| 
				SFTP_SSH2_FEAT_MAC_LEN,			NULL },

  { "^2\\.0\\..*",		SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO_IN_DSA_SIG|
				SFTP_SSH2_FEAT_SERVICE_IN_PUBKEY_SIG|
    				SFTP_SSH2_FEAT_HAVE_PUBKEY_ALGO| 
				SFTP_SSH2_FEAT_CIPHER_USE_K|
				SFTP_SSH2_FEAT_MAC_LEN,			NULL },

  { "^2\\.2\\.0.*|"
    "^2\\.3\\.0.*",		SFTP_SSH2_FEAT_MAC_LEN,			NULL },


  { "^1\\.2\\.18.*|"
    "^1\\.2\\.19.*|"
    "^1\\.2\\.20.*|"
    "^1\\.2\\.21.*|"
    "^1\\.2\\.22.*|"
    "^1\\.3\\.2.*|"		
    "^3\\.2\\.9.*",		SFTP_SSH2_FEAT_IGNORE_MSG,		NULL },

  { ".*PuTTY.*|"
    ".*PUTTY.*|"
    ".*WinSCP.*",		SFTP_SSH2_FEAT_NO_DATA_WHILE_REKEYING,	NULL },

  { ".*SSH_Version_Mapper.*",	SFTP_SSH2_FEAT_SCANNER,			NULL },

  { "^Probe-.*", 		SFTP_SSH2_FEAT_PROBE,			NULL },

  { NULL, 0, NULL },
};

static const char *trace_channel = "ssh2";

int sftp_interop_handle_version(pool *p, const char *client_version) {
  register unsigned int i;
  size_t version_len;
  const char *version = NULL;
  char *ptr = NULL;
  int is_probe = FALSE, is_scan = FALSE;
  config_rec *c;

  if (client_version == NULL) {
    errno = EINVAL;
    return -1;
  }

  version_len = strlen(client_version);

  /* The version string MUST conform to the following, as per Section 4.2
   * of RFC4253:
   *
   *  SSH-protoversion-softwareversion [SP comments]
   *
   * The 'comments' field is optional.  The 'protoversion' MUST be "2.0".
   * The 'softwareversion' field MUST be printable ASCII characters and
   * cannot contain SP or the '-' character.
   */

  for (i = 0; i < version_len; i++) {
    if (!PR_ISPRINT(client_version[i]) &&
        client_version[i] != '-' &&
        client_version[i] != ' ') {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client-sent version contains non-printable or illegal characters, "
        "disconnecting client");
      SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
        NULL);
    }
  }

  /* Skip past the leading "SSH-2.0-" (or "SSH-1.99-") to get the actual
   * client info.
   */
  if (strncmp(client_version, "SSH-2.0-", 8) == 0) {
    version = pstrdup(p, client_version + 8);

  } else if (strncmp(client_version, "SSH-1.99-", 9) == 0) {
    version = pstrdup(p, client_version + 9);

  } else {
    /* An illegally formatted client version.  How did it get here? */
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client-sent version (%s) is illegally formmated, disconnecting client",
      client_version);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
      NULL);
  }

  /* Look for the optional comments field in the received client version; if
   * present, trim it out, so that we do not try to match on it.
   */
  ptr = strchr(version, ' ');
  if (ptr != NULL) {
    pr_trace_msg(trace_channel, 11, "read client version with comments: '%s'",
      version);
    *ptr = '\0';
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "handling connection from SSH2 client '%s'", version);
  pr_trace_msg(trace_channel, 5, "handling connection from SSH2 client '%s'",
    version);

  /* First matching pattern wins. */
  for (i = 0; known_versions[i].pattern != NULL; i++) {
    int res;

    pr_signals_handle();

    pr_trace_msg(trace_channel, 18,
      "checking client version '%s' against regex '%s'", version,
      known_versions[i].pattern);

    res = pr_regexp_exec(known_versions[i].pre, version, 0, NULL, 0, 0, 0);
    if (res == 0) {
      pr_trace_msg(trace_channel, 18,
        "client version '%s' matched against regex '%s'", version,
        known_versions[i].pattern);

      /* We have a match. */
      default_flags &= ~(known_versions[i].disabled_flags);

      if (known_versions[i].disabled_flags == SFTP_SSH2_FEAT_PROBE) {
        is_probe = TRUE;
      }

      if (known_versions[i].disabled_flags == SFTP_SSH2_FEAT_SCANNER) {
        is_scan = TRUE;
      }

      break;

    } else {
      pr_trace_msg(trace_channel, 18,
        "client version '%s' did not match regex '%s'", version,
        known_versions[i].pattern);
    }
  }

  /* Disconnect probes/scans here. */
  if (is_probe) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SSH2 probe from '%s', disconnecting", version);

    /* We should use the PROTOCOL_VERSION_NOT_SUPPORTED disconnect code,
     * but for probes/scans, simply hanging up on the client seems better.
     */
    pr_session_disconnect(&sftp_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  if (is_scan) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SSH2 scan from '%s', disconnecting", version);

    /* We should use the PROTOCOL_VERSION_NOT_SUPPORTED disconnect code,
     * but for probes/scans, simply hanging up on the client seems better.
     */
    pr_session_disconnect(&sftp_module, PR_SESS_DISCONNECT_BY_APPLICATION,
      NULL);
  }

  /* Now iterate through any SFTPClientMatch rules. */

  c = find_config(main_server->conf, CONF_PARAM, "SFTPClientMatch", FALSE);
  while (c) {
    int res;
    char *pattern;
    pr_regex_t *pre;

    pr_signals_handle();

    pattern = c->argv[0];
    pre = c->argv[1];

    pr_trace_msg(trace_channel, 18,
      "checking client version '%s' against SFTPClientMatch regex '%s'",
      version, pattern);

    res = pr_regexp_exec(pre, version, 0, NULL, 0, 0, 0);
    if (res == 0) {
      pr_table_t *tab;
      const void *v, *v2;

      /* We have a match. */

      tab = c->argv[2];

      /* Look for the following keys:
       *
       *  channelWindowSize
       *  channelPacketSize
       *  pessimisticNewkeys
       *  sftpMinProtocolVersion
       *  sftpMaxProtocolVersion
       *  sftpUTF8ProtocolVersion (only if NLS support is enabled)
       */

      v = pr_table_get(tab, "channelWindowSize", NULL);
      if (v != NULL) {
        uint32_t window_size;

        window_size = *((uint32_t *) v);

        pr_trace_msg(trace_channel, 16, "setting max server channel window "
          "size to %lu bytes, as per SFTPClientMatch",
          (unsigned long) window_size);

        sftp_channel_set_max_windowsz(window_size);
      }
      
      v = pr_table_get(tab, "channelPacketSize", NULL);
      if (v != NULL) {
        uint32_t packet_size;

        packet_size = *((uint32_t *) v);

        pr_trace_msg(trace_channel, 16, "setting max server channel packet "
          "size to %lu bytes, as per SFTPClientMatch",
          (unsigned long) packet_size);

        sftp_channel_set_max_packetsz(packet_size);
      }

      v = pr_table_get(tab, "pessimisticNewkeys", NULL);
      if (v != NULL) {
        int pessimistic_newkeys;

        pessimistic_newkeys = *((int *) v);

        pr_trace_msg(trace_channel, 16,
          "setting pessimistic NEWKEYS behavior to %s, as per SFTPClientMatch",
          pessimistic_newkeys ? "true" : "false");

        if (pessimistic_newkeys) {
          default_flags |= SFTP_SSH2_FEAT_PESSIMISTIC_NEWKEYS;
        } 
      }

      v = pr_table_get(tab, "sftpMinProtocolVersion", NULL);
      v2 = pr_table_get(tab, "sftpMaxProtocolVersion", NULL);
      if (v != NULL &&
          v2 != NULL) {
        unsigned int min_version, max_version;

        min_version = *((unsigned int *) v);
        max_version = *((unsigned int *) v2);

        if (min_version != max_version) {
          pr_trace_msg(trace_channel, 16, "setting SFTP protocol version "
            "range %u-%u, as per SFTPClientMatch", min_version,
            max_version);

        } else {
          pr_trace_msg(trace_channel, 16, "setting SFTP protocol version "
            "%u, as per SFTPClientMatch", min_version);
        }

        sftp_fxp_set_protocol_version(min_version, max_version);
      }

#ifdef PR_USE_NLS
      v = pr_table_get(tab, "sftpUTF8ProtocolVersion", NULL);
      if (v != NULL) {
        unsigned int protocol_version;

        protocol_version = *((unsigned int *) v);
        pr_trace_msg(trace_channel, 16, "setting SFTP UTF8 protocol version "
          "%u, as per SFTPClientMatch", protocol_version);

        sftp_fxp_set_utf8_protocol_version(protocol_version);
      }
#endif /* PR_USE_NLS */

      /* Once we're done, we can destroy the table. */
      (void) pr_table_empty(tab);
      (void) pr_table_free(tab);
      c->argv[2] = NULL;
 
    } else {
      pr_trace_msg(trace_channel, 18,
        "client version '%s' did not match SFTPClientMatch regex '%s'", version,
        pattern);
    }

    c = find_config_next(c, c->next, CONF_PARAM, "SFTPClientMatch", FALSE);
  }

  return 0;
}

int sftp_interop_supports_feature(int feat_flag) {
  switch (feat_flag) {
    case SFTP_SSH2_FEAT_PROBE:
    case SFTP_SSH2_FEAT_SCANNER:
      /* Scanners and probes would have been disconnected by now. */
      return FALSE;

    default:
      if (!(default_flags & feat_flag)) {
        return FALSE;
      }
  }

  return TRUE;
}

int sftp_interop_init(void) {
  register unsigned int i;

  /* Compile the regexps for all of the known client versions, to save the
   * time when a client connects.
   */
  for (i = 0; known_versions[i].pattern != NULL; i++) {
    pr_regex_t *pre;
    int res;

    pr_signals_handle();

    pre = pr_regexp_alloc(&sftp_module);

    res = pr_regexp_compile(pre, known_versions[i].pattern,
      REG_EXTENDED|REG_NOSUB);
    if (res != 0) {
      char errmsg[256];

      memset(errmsg, '\0', sizeof(errmsg));
      pr_regexp_error(res, pre, errmsg, sizeof(errmsg));
      pr_regexp_free(NULL, pre);

      pr_log_debug(DEBUG0, MOD_SFTP_VERSION
        ": error compiling regex pattern '%s' (known_versions[%u]): %s",
        known_versions[i].pattern, i, errmsg);
      continue;
    }

    known_versions[i].pre = pre;
  }

  return 0;
}

int sftp_interop_free(void) {
  register unsigned int i;

  for (i = 0; known_versions[i].pattern != NULL; i++) {
    if (known_versions[i].pre != NULL) {
      pr_regexp_free(NULL, known_versions[i].pre);
      known_versions[i].pre = NULL;
    }
  }

  return 0;
}
