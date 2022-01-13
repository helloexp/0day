/*
 * ProFTPD - mod_sftp sftp
 * Copyright (c) 2008-2019 TJ Saunders
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
#include "msg.h"
#include "crypto.h"
#include "packet.h"
#include "disconnect.h"
#include "channel.h"
#include "auth.h"
#include "display.h"
#include "fxp.h"
#include "utf8.h"
#include "misc.h"

/* FXP_NAME file attribute flags */
#define SSH2_FX_ATTR_SIZE		0x00000001
#define SSH2_FX_ATTR_UIDGID		0x00000002
#define SSH2_FX_ATTR_PERMISSIONS	0x00000004 
#define SSH2_FX_ATTR_ACMODTIME		0x00000008
#define SSH2_FX_ATTR_ACCESSTIME         SSH2_FX_ATTR_ACMODTIME
#define SSH2_FX_ATTR_CREATETIME		0x00000010
#define SSH2_FX_ATTR_MODIFYTIME		0x00000020
#define SSH2_FX_ATTR_ACL		0x00000040
#define SSH2_FX_ATTR_OWNERGROUP		0x00000080
#define SSH2_FX_ATTR_SUBSECOND_TIMES	0x00000100
#define SSH2_FX_ATTR_BITS		0x00000200

/* Note that these attributes were added in draft-ietf-secsh-filexfer-06,
 * which is SFTP protocol version 6.
 */
#define SSH2_FX_ATTR_ALLOCATION_SIZE	0x00000400
#define SSH2_FX_ATTR_TEXT_HINT		0x00000800
#define SSH2_FX_ATTR_MIME_TYPE		0x00001000
#define SSH2_FX_ATTR_LINK_COUNT		0x00002000
#define SSH2_FX_ATTR_UNTRANSLATED_NAME	0x00004000

#define SSH2_FX_ATTR_CTIME		0x00008000

/* The EXTENDED attribute was defined in draft-ietf-secsh-filexfer-02,
 * which is SFTP protocol version 3.
 */
#define SSH2_FX_ATTR_EXTENDED		0x80000000

/* FX_ATTR_BITS values (see draft-ietf-secsh-filexfer-13, Section 7.9) */
#define SSH2_FX_ATTR_BIT_FL_READONLY		0x00000001
#define SSH2_FX_ATTR_BIT_FL_SYSTEM		0x00000002
#define SSH2_FX_ATTR_BIT_FL_HIDDEN		0x00000004
#define SSH2_FX_ATTR_BIT_FL_CASE_INSENSITIVE	0x00000008
#define SSH2_FX_ATTR_BIT_FL_ARCHIVE		0x00000010
#define SSH2_FX_ATTR_BIT_FL_ENCRYPTED		0x00000020
#define SSH2_FX_ATTR_BIT_FL_COMPRESSED		0x00000040
#define SSH2_FX_ATTR_BIT_FL_SPARSE		0x00000080
#define SSH2_FX_ATTR_BIT_FL_APPEND_ONLY		0x00000100
#define SSH2_FX_ATTR_BIT_FL_IMMUTABLE		0x00000200
#define SSH2_FX_ATTR_BIT_FL_SYNC		0x00000400
#define SSH2_FX_ATTR_BIT_FL_TRANSLATION_ERR	0x00000800

/* FX_ATTR_TEXT_HINT values (see draft-ietf-secsh-filexfer-13, Section 7.10) */
#define SSH2_FX_ATTR_KNOWN_TEXT		0x00
#define SSH2_FX_ATTR_GUESSED_TEXT	0x01
#define SSH2_FX_ATTR_KNOWN_BINARY	0x02
#define SSH2_FX_ATTR_GUESSED_BINARY	0x03

/* FXP_ATTRS file types */
#define SSH2_FX_ATTR_FTYPE_REGULAR		1
#define SSH2_FX_ATTR_FTYPE_DIRECTORY		2
#define SSH2_FX_ATTR_FTYPE_SYMLINK		3
#define SSH2_FX_ATTR_FTYPE_SPECIAL		4
#define SSH2_FX_ATTR_FTYPE_UNKNOWN		5
#define SSH2_FX_ATTR_FTYPE_SOCKET		6
#define SSH2_FX_ATTR_FTYPE_CHAR_DEVICE		7
#define SSH2_FX_ATTR_FTYPE_BLOCK_DEVICE		8
#define SSH2_FX_ATTR_FTYPE_FIFO			9

/* FXP_LOCK/FXP_UNLOCK flags */
#define SSH2_FXL_READ			0x00000040
#define SSH2_FXL_WRITE			0x00000080
#define SSH2_FXL_DELETE			0x00000100

/* FXP_OPEN flags (prior to version 5) */
#define SSH2_FXF_READ			0x00000001
#define SSH2_FXF_WRITE			0x00000002
#define SSH2_FXF_APPEND			0x00000004
#define SSH2_FXF_CREAT			0x00000008
#define SSH2_FXF_TRUNC			0x00000010
#define SSH2_FXF_EXCL			0x00000020
#define SSH2_FXF_TEXT			0x00000040

/* FXP_OPEN flags (version 5 and higher) */
#define SSH2_FXF_WANT_READ_DATA		0x00000001
#define SSH2_FXF_WANT_WRITE_DATA	0x00000002
#define SSH2_FXF_WANT_APPEND_DATA	0x00000004
#define SSH2_FXF_WANT_READ_NAMED_ATTRS	0x00000008
#define SSH2_FXF_WANT_WRITE_NAMED_ATTRS	0x00000010
#define SSH2_FXF_WANT_READ_ATTRIBUTES	0x00000080
#define SSH2_FXF_WANT_WRITE_ATTRIBUTES	0x00000100
#define SSH2_FXF_WANT_READ_ACL		0x00020000
#define SSH2_FXF_WANT_WRITE_ACL		0x00040000
#define SSH2_FXF_WANT_WRITE_OWNER	0x00080000

#define SSH2_FXF_CREATE_NEW			0x00000000
#define SSH2_FXF_CREATE_TRUNCATE		0x00000001
#define SSH2_FXF_OPEN_EXISTING			0x00000002
#define SSH2_FXF_OPEN_OR_CREATE			0x00000003
#define SSH2_FXF_TRUNCATE_EXISTING		0x00000004
#define SSH2_FXF_ACCESS_APPEND_DATA		0x00000008
#define SSH2_FXF_ACCESS_APPEND_DATA_ATOMIC	0x00000010
#define SSH2_FXF_ACCESS_TEXT_MODE		0x00000020

/* These are the BLOCK_{READ,WRITE,DELETE} values from Section 8.1.1.3 of
 * the SFTP Draft.
 */
#define SSH2_FXF_ACCESS_READ_LOCK		0x00000040
#define SSH2_FXF_ACCESS_WRITE_LOCK		0x00000080
#define SSH2_FXF_ACCESS_DELETE_LOCK		0x00000100

/* FXP_REALPATH control values */
#define SSH2_FXRP_NO_CHECK		0x00000001
#define SSH2_FXRP_STAT_IF		0x00000002
#define SSH2_FXRP_STAT_ALWAYS		0x00000003

/* FXP_RENAME flags */
#define SSH2_FXR_OVERWRITE		0x00000001
#define SSH2_FXR_ATOMIC			0x00000002
#define SSH2_FXR_NATIVE			0x00000004

/* FXP_STATUS codes */
#define SSH2_FX_OK				0
#define SSH2_FX_EOF				1
#define SSH2_FX_NO_SUCH_FILE			2
#define SSH2_FX_PERMISSION_DENIED		3
#define SSH2_FX_FAILURE				4
#define SSH2_FX_BAD_MESSAGE			5
#define SSH2_FX_NO_CONNECTION			6
#define SSH2_FX_CONNECTION_LOST			7
#define SSH2_FX_OP_UNSUPPORTED			8
#define SSH2_FX_INVALID_HANDLE			9
#define SSH2_FX_NO_SUCH_PATH			10
#define SSH2_FX_FILE_ALREADY_EXISTS		11
#define SSH2_FX_WRITE_PROTECT			12
#define SSH2_FX_NO_MEDIA			13
#define SSH2_FX_NO_SPACE_ON_FILESYSTEM		14
#define SSH2_FX_QUOTA_EXCEEDED			15
#define SSH2_FX_UNKNOWN_PRINCIPAL		16
#define SSH2_FX_LOCK_CONFLICT			17
#define SSH2_FX_DIR_NOT_EMPTY			18
#define SSH2_FX_NOT_A_DIRECTORY			19
#define SSH2_FX_INVALID_FILENAME		20
#define SSH2_FX_LINK_LOOP			21
#define SSH2_FX_CANNOT_DELETE			22
#define SSH2_FX_INVALID_PARAMETER		23
#define SSH2_FX_FILE_IS_A_DIRECTORY		24
#define SSH2_FX_BYTE_RANGE_LOCK_CONFLICT	25
#define SSH2_FX_BYTE_RANGE_LOCK_REFUSED		26
#define SSH2_FX_DELETE_PENDING			27
#define SSH2_FX_FILE_CORRUPT			28
#define SSH2_FX_OWNER_INVALID			29
#define SSH2_FX_GROUP_INVALID			30
#define SSH2_FX_NO_MATCHING_BYTE_RANGE_LOCK	31

/* statvfs@openssh.com extension flags */
#define SSH2_FXE_STATVFS_ST_RDONLY		0x1
#define SSH2_FXE_STATVFS_ST_NOSUID		0x2

/* xattr@proftpd.org extension flags */
#define SSH2_FXE_XATTR_CREATE			0x1
#define SSH2_FXE_XATTR_REPLACE			0x2

extern pr_response_t *resp_list, *resp_err_list;

struct fxp_dirent {
  const char *client_path;
  const char *real_path;
  struct stat *st;
};

struct fxp_handle {
  pool *pool;
  const char *name;

  pr_fh_t *fh;
  int fh_flags;

  /* For indicating whether the file existed prior to being opened/created. */
  int fh_existed;

  /* For supporting the HiddenStores directive */
  char *fh_real_path;

  /* For referencing information about the opened file; NOTE THAT THIS MAY
   * BE STALE.
   */
  struct stat *fh_st;

  /* For tracking the number of bytes transferred for this file; for
   * better TransferLog tracking.
   */
  size_t fh_bytes_xferred;

  void *dirh;
  const char *dir;
};

struct fxp_packet {
  pool *pool;
  uint32_t channel_id;
  uint32_t packet_len;
  unsigned char request_type;
  uint32_t request_id;
  uint32_t payload_sz;
  unsigned char *payload;
  uint32_t payload_len;

  unsigned int state;
};

struct fxp_buffer {
  /* Pointer to the start of the buffer */
  unsigned char *ptr;

  /* Total size of the buffer */
  uint32_t bufsz;

  /* Current pointer */
  unsigned char *buf;

  /* Length of buffer remaining */
  uint32_t buflen;
};

#define	FXP_PACKET_HAVE_PACKET_LEN	0x0001
#define	FXP_PACKET_HAVE_REQUEST_TYPE	0x0002
#define	FXP_PACKET_HAVE_REQUEST_ID	0x0004
#define	FXP_PACKET_HAVE_PAYLOAD_SIZE	0x0008
#define	FXP_PACKET_HAVE_PAYLOAD		0x0010

/* After 32K of allocation from the scratch SFTP payload pool, destroy the
 * pool and create a new one.  This will prevent unbounded allocation
 * from the pool.
 */
#define FXP_PACKET_DATA_ALLOC_MAX_SZ		(1024 * 32)
static size_t fxp_packet_data_allocsz = 0;

#define FXP_PACKET_DATA_DEFAULT_SZ		(1024 * 16)
#define FXP_RESPONSE_DATA_DEFAULT_SZ		512

#ifdef PR_USE_XATTR
/* Allocate larger buffers for extended attributes */
# define FXP_RESPONSE_NAME_DEFAULT_SZ		(1024 * 4)
#endif /* PR_USE_XATTR */

#ifndef FXP_RESPONSE_NAME_DEFAULT_SZ
# define FXP_RESPONSE_NAME_DEFAULT_SZ		FXP_RESPONSE_DATA_DEFAULT_SZ
#endif

#define FXP_MAX_PACKET_LEN			(1024 * 512)

/* Maximum number of SFTP extended attributes we accept at one time. */
#ifndef FXP_MAX_EXTENDED_ATTRIBUTES
# define FXP_MAX_EXTENDED_ATTRIBUTES		100
#endif

/* Maximum length of SFTP extended attribute name OR value. */
#ifndef FXP_MAX_EXTENDED_ATTR_LEN
# define FXP_MAX_EXTENDED_ATTR_LEN		1024
#endif

struct fxp_extpair {
  char *ext_name;
  uint32_t ext_datalen;
  unsigned char *ext_data;
};

static pool *fxp_pool = NULL;
static int fxp_use_gmt = TRUE;

/* FSOptions */
static unsigned long fxp_fsio_opts = 0UL;
static unsigned int fxp_min_client_version = 1;
static unsigned int fxp_max_client_version = 6;
static unsigned int fxp_utf8_protocol_version = 4;
static unsigned long fxp_ext_flags = SFTP_FXP_EXT_DEFAULT;

static pr_fh_t *fxp_displaylogin_fh = NULL;
static int fxp_sent_display_login_file = FALSE;

/* For handling "version-select" requests properly (or rejecting them as
 * necessary.
 */
static int allow_version_select = FALSE;

/* Use a struct to maintain the per-channel FXP-specific values. */
struct fxp_session {
  struct fxp_session *next, *prev;

  pool *pool;
  uint32_t channel_id;
  uint32_t client_version;
  pr_table_t *handle_tab;
};

static struct fxp_session *fxp_session = NULL, *fxp_sessions = NULL;

static const char *trace_channel = "sftp";

/* Necessary prototypes */
static struct fxp_handle *fxp_handle_get(const char *);
static struct fxp_packet *fxp_packet_create(pool *, uint32_t);
static int fxp_packet_write(struct fxp_packet *);

static struct fxp_session *fxp_get_session(uint32_t channel_id) {
  struct fxp_session *sess;

  sess = fxp_sessions;
  while (sess) {
    pr_signals_handle();

    if (sess->channel_id == channel_id) {
      return sess;
    }

    sess = sess->next;
  }

  errno = ENOENT;
  return NULL;
}

static int fxp_timeout_stalled_cb(CALLBACK_FRAME) {
  pr_event_generate("core.timeout-stalled", NULL);

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "SFTP data transfer stalled timeout (%d secs) reached",
    pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED));
  SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION,
    "data stalled timeout reached");

  return 0;
}

static cmd_rec *fxp_cmd_alloc(pool *p, const char *name, char *arg) {
  cmd_rec *cmd;

  cmd = pr_cmd_alloc(p, 2, pstrdup(p, name), arg ? arg : "");
  cmd->arg = arg;

  return cmd;
}

static const char *fxp_strerror(uint32_t status) {
    switch (status) {
      case SSH2_FX_OK:
        return "OK";

      case SSH2_FX_EOF:
        return "End of file";

      case SSH2_FX_NO_SUCH_FILE:
        return "No such file";

      case SSH2_FX_PERMISSION_DENIED:
        return "Permission denied";

      case SSH2_FX_BAD_MESSAGE:
        return "Bad message";

      case SSH2_FX_OP_UNSUPPORTED:
        return "Unsupported operation";

      case SSH2_FX_INVALID_HANDLE:
        return "Invalid handle";

      case SSH2_FX_NO_SUCH_PATH:
        return "No such path";

      case SSH2_FX_FILE_ALREADY_EXISTS:
        return "File already exists";

      case SSH2_FX_NO_SPACE_ON_FILESYSTEM:
        return "Out of disk space";

      case SSH2_FX_QUOTA_EXCEEDED:
        return "Quota exceeded";

      case SSH2_FX_UNKNOWN_PRINCIPAL:
        return "Unknown principal";

      case SSH2_FX_LOCK_CONFLICT:
        return "Lock conflict";

      case SSH2_FX_DIR_NOT_EMPTY:
        return "Directory is not empty";

      case SSH2_FX_NOT_A_DIRECTORY:
        return "Not a directory";

      case SSH2_FX_INVALID_FILENAME:
        return "Invalid filename";

      case SSH2_FX_LINK_LOOP:
        return "Link loop";

      case SSH2_FX_INVALID_PARAMETER:
        return "Invalid parameter";

      case SSH2_FX_FILE_IS_A_DIRECTORY:
        return "File is a directory";

      case SSH2_FX_OWNER_INVALID:
        return "Invalid owner";

      case SSH2_FX_GROUP_INVALID:
        return "Invalid group";
    }

    return "Failure";
}

static uint32_t fxp_errno2status(int xerrno, const char **reason) {
  uint32_t status_code = SSH2_FX_FAILURE;

  /* Provide a default reason string; it will be overwritten below by a
   * more appropriate string as necessary.
   */ 
  if (reason) {
    *reason = fxp_strerror(status_code);
  }

  switch (xerrno) {
    case 0:
      status_code = SSH2_FX_OK;
      if (reason) {
        *reason = fxp_strerror(status_code);
      }
      break;

    case EOF:
      status_code = SSH2_FX_EOF;
      if (reason) {
        *reason = fxp_strerror(status_code);
      }
      break;

    case EBADF:
    case ENOENT:
#ifdef ENXIO
    case ENXIO:
#endif
#if defined(ENODATA)
    case ENODATA:
#endif
#if defined(ENOATTR) && defined(ENODATA) && ENOATTR != ENODATA
    case ENOATTR:
#endif
      status_code = SSH2_FX_NO_SUCH_FILE;
      if (reason) {
        *reason = fxp_strerror(status_code);
      }
      break;

    case EACCES:
    case EPERM:
      status_code = SSH2_FX_PERMISSION_DENIED;
      if (reason) {
        *reason = fxp_strerror(status_code);
      }
      break;

    case EIO:
    case EXDEV:
      if (reason) {
        *reason = strerror(xerrno);
      }
      break;

    case ENOSYS:
#ifdef ENOTSUP
    case ENOTSUP:
#endif
      status_code = SSH2_FX_OP_UNSUPPORTED;
      if (reason) {
        *reason = fxp_strerror(status_code);
      }
      break;

    case EFAULT:
    case EINVAL:
#ifdef E2BIG
    case E2BIG:
#endif
#ifdef ERANGE
    case ERANGE:
#endif
      if (reason) {
        *reason = fxp_strerror(SSH2_FX_INVALID_PARAMETER);
      }

      if (fxp_session->client_version > 5) {
        status_code = SSH2_FX_INVALID_PARAMETER;

      } else {
        status_code = SSH2_FX_OP_UNSUPPORTED;
      }
      break;

    case EEXIST:
      if (reason) {
        *reason = fxp_strerror(SSH2_FX_FILE_ALREADY_EXISTS);
      }

      if (fxp_session->client_version > 3) {
        status_code = SSH2_FX_FILE_ALREADY_EXISTS;
      }
      break;

#ifdef EDQUOT
    case EDQUOT:
      if (reason) {
        *reason = fxp_strerror(SSH2_FX_QUOTA_EXCEEDED);
      }

      if (fxp_session->client_version > 4) {
        status_code = SSH2_FX_QUOTA_EXCEEDED;
      }
      break;
#endif

#ifdef EFBIG
    case EFBIG:
#endif
#ifdef ENOSPC
    case ENOSPC:
#endif
      if (reason) {
        *reason = fxp_strerror(SSH2_FX_NO_SPACE_ON_FILESYSTEM);
      }

      if (fxp_session->client_version > 4) {
        status_code = SSH2_FX_NO_SPACE_ON_FILESYSTEM;
      }
      break;

    case EISDIR:
      if (reason) {
        *reason = fxp_strerror(SSH2_FX_FILE_IS_A_DIRECTORY);
      }

      if (fxp_session->client_version > 5) {
        status_code = SSH2_FX_FILE_IS_A_DIRECTORY;
      }
      break;

    case ENOTDIR:
      if (reason) {
        *reason = fxp_strerror(SSH2_FX_NOT_A_DIRECTORY);
      }

      if (fxp_session->client_version > 5) {
        status_code = SSH2_FX_NOT_A_DIRECTORY;
      }
      break;

    case ELOOP:
      if (reason) {
        *reason = fxp_strerror(SSH2_FX_LINK_LOOP);
      }

      if (fxp_session->client_version > 5) {
        status_code = SSH2_FX_LINK_LOOP;
      }
      break;

#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
      if (reason) {
        *reason = fxp_strerror(SSH2_FX_INVALID_FILENAME);
      }

      if (fxp_session->client_version > 5) {
        status_code = SSH2_FX_INVALID_FILENAME;
      }
      break;
#endif

     /* On AIX5, ENOTEMPTY and EEXIST are defined to be the same value.
      * And using the same value multiple times in a switch statement
      * causes compiler grief.  See:
      *
      *  http://forums.proftpd.org/smf/index.php/topic,3971.0.html
      *
      * To handle this, then, we only use ENOTEMPTY if it is defined to
      * be a different value than EEXIST.  We'll have an AIX-specific
      * check for this particular error case in the fxp_handle_rmdir()
      * function.
      */
#if defined(ENOTEMPTY) && ENOTEMPTY != EEXIST
    case ENOTEMPTY:
      if (reason) {
        *reason = fxp_strerror(SSH2_FX_DIR_NOT_EMPTY);
      }

      if (fxp_session->client_version > 5) {
        status_code = SSH2_FX_DIR_NOT_EMPTY;
      }
      break;
#endif
  }

  return status_code;
}

static void fxp_set_filehandle_note(cmd_rec *cmd, struct fxp_handle *fxh) {
  if (pr_table_add(cmd->notes, "sftp.file-handle", (char *) fxh->name, 0) < 0) {
    int xerrno = errno;

    if (xerrno != EEXIST) {
      pr_trace_msg(trace_channel, 8,
        "error setting 'sftp.file-handle' note: %s", strerror(xerrno));
    }
  }
}

static void fxp_trace_v3_open_flags(pool *p, uint32_t flags) {
  char *flags_str = "";
  int trace_level = 15;

  if (pr_trace_get_level(trace_channel) < trace_level) {
    return;
  }

  if (flags & SSH2_FXF_READ) {
    flags_str = pstrcat(p, flags_str, "FXF_READ", NULL);
  }

  if (flags & SSH2_FXF_WRITE) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FXF_WRITE", NULL);
  }

  if (flags & SSH2_FXF_APPEND) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FXF_APPEND", NULL);
  }

  if (flags & SSH2_FXF_CREAT) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FXF_CREAT", NULL);
  }

  if (flags & SSH2_FXF_TRUNC) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FXF_TRUNC", NULL);
  }

  if (flags & SSH2_FXF_EXCL) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FXF_EXCL", NULL);
  }

  if (flags & SSH2_FXF_TEXT) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FXF_TEXT", NULL);
  }

  pr_trace_msg(trace_channel, trace_level, "OPEN flags = %s", flags_str);
}

/* Map the FXP_OPEN flags to POSIX flags. */
static int fxp_get_v3_open_flags(uint32_t flags) {
  int res = 0;

  if (flags & SSH2_FXF_READ) {
    if (flags & SSH2_FXF_WRITE) {
      res = O_RDWR;

#ifdef O_APPEND
      if (flags & SSH2_FXF_APPEND) {
        res |= O_APPEND;
      }
#endif

    } else {
      res = O_RDONLY;
    }

  } else if (flags & SSH2_FXF_WRITE) {
    res = O_WRONLY;

#ifdef O_APPEND
    if (flags & SSH2_FXF_APPEND) {
      res |= O_APPEND;
    }
#endif

  } else if (flags & SSH2_FXF_APPEND) {
    /* Assume FXF_WRITE, since the client didn't explicitly provide either
     * FXF_READ or FXF_WRITE.
     */
    res = O_WRONLY|O_APPEND;
  }

  if (flags & SSH2_FXF_CREAT) {
    res |= O_CREAT;

    /* Since the behavior of open(2) when O_EXCL is set and O_CREAT is not
     * set is undefined, we avoid that situation, and only check for the
     * FXF_EXCL SSH flag if the FXF_CREAT flag is set.
     */
    if (flags & SSH2_FXF_EXCL) {
      res |= O_EXCL;
    }
  }

  if (flags & SSH2_FXF_TRUNC) {
    res |= O_TRUNC;
  }

  return res;
}

static void fxp_trace_v5_bit_flags(pool *p, uint32_t attr_bits,
    uint32_t attr_valid_bits) {
  uint32_t flags;
  char *flags_str = "";
  int trace_level = 15;

  if (pr_trace_get_level(trace_channel) < trace_level) {
    return;
  }

  /* We're only interested in which, of the valid bits, are turned on/enabled
   * in the bits value, for logging.
   */

  flags = (attr_bits & attr_valid_bits);

  if (flags & SSH2_FX_ATTR_BIT_FL_READONLY) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_READONLY", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_SYSTEM) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_SYSTEM", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_HIDDEN) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_HIDDEN", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_CASE_INSENSITIVE) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_CASE_INSENSITIVE", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_ARCHIVE) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_ARCHIVE", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_ENCRYPTED) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_ENCRYPTED", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_COMPRESSED) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_COMPRESSED", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_SPARSE) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_SPARSE", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_APPEND_ONLY) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_APPEND_ONLY", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_IMMUTABLE) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_IMMUTABLE", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_SYNC) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_SYNC", NULL);
  }

  if (flags & SSH2_FX_ATTR_BIT_FL_TRANSLATION_ERR) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FLAGS_TRANSLATION_ERR", NULL);
  }

  pr_trace_msg(trace_channel, 15,
    "protocol version %lu: read BITS attribute: bits %s requested",
    (unsigned long) fxp_session->client_version, flags_str);
}

static void fxp_trace_v5_open_flags(pool *p, uint32_t desired_access,
    uint32_t flags) {
  uint32_t base_flag;
  char *access_str = "", *flags_str = "";
  int trace_level = 15;

  if (pr_trace_get_level(trace_channel) < trace_level) {
    return;
  }

  /* The flags value, in the case of v5 (and later) OPEN requests, has
   * a "base" value, along with some modifying bits masked in.
   */

  base_flag = (flags &~ (SSH2_FXF_ACCESS_APPEND_DATA|SSH2_FXF_ACCESS_APPEND_DATA_ATOMIC|SSH2_FXF_ACCESS_TEXT_MODE));

  switch (base_flag) {
    case SSH2_FXF_CREATE_NEW:
      flags_str = pstrcat(p, flags_str, "FXF_CREATE_NEW", NULL);
      break;

    case SSH2_FXF_CREATE_TRUNCATE:
      flags_str = pstrcat(p, flags_str, "FXF_CREATE_TRUNCATE", NULL);
      break;

    case SSH2_FXF_OPEN_EXISTING:
      flags_str = pstrcat(p, flags_str, "FXF_OPEN_EXISTING", NULL);
      break;

    case SSH2_FXF_OPEN_OR_CREATE:
      flags_str = pstrcat(p, flags_str, "FXF_OPEN_OR_CREATE", NULL);
      break;

    case SSH2_FXF_TRUNCATE_EXISTING:
      flags_str = pstrcat(p, flags_str, "FXF_TRUNCATE_EXISTING", NULL);
      break;

    default:
      flags_str = pstrcat(p, flags_str, "<unknown>", NULL);
  }

  if (flags & SSH2_FXF_ACCESS_APPEND_DATA) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FXF_ACCESS_APPEND_DATA", NULL);
  }

  if (flags & SSH2_FXF_ACCESS_APPEND_DATA_ATOMIC) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FXF_ACCESS_APPEND_DATA_ATOMIC", NULL);
  }

  if (flags & SSH2_FXF_ACCESS_TEXT_MODE) {
    flags_str = pstrcat(p, flags_str, *flags_str ? "|" : "",
      "FXF_ACCESS_TEXT_MODE", NULL);
  }

  if (desired_access & SSH2_FXF_WANT_READ_DATA) {
    access_str = pstrcat(p, access_str, "FXF_WANT_READ_DATA", NULL);
  }

  if (desired_access & SSH2_FXF_WANT_WRITE_DATA) {
    access_str = pstrcat(p, access_str, *access_str ? "|" : "",
      "FXF_WANT_WRITE_DATA", NULL);
  }

  if (desired_access & SSH2_FXF_WANT_APPEND_DATA) {
    access_str = pstrcat(p, access_str, *access_str ? "|" : "",
      "FXF_WANT_APPEND_DATA", NULL);
  }

  if (desired_access & SSH2_FXF_WANT_READ_NAMED_ATTRS) {
    access_str = pstrcat(p, access_str, *access_str ? "|" : "",
      "FXF_WANT_READ_NAMED_ATTRS", NULL);
  }

  if (desired_access & SSH2_FXF_WANT_WRITE_NAMED_ATTRS) {
    access_str = pstrcat(p, access_str, *access_str ? "|" : "",
      "FXF_WANT_WRITE_NAMED_ATTRS", NULL);
  }

  if (desired_access & SSH2_FXF_WANT_WRITE_ATTRIBUTES) {
    access_str = pstrcat(p, access_str, *access_str ? "|" : "",
      "FXF_WANT_WRITE_ATTRS", NULL);
  }

  if (desired_access & SSH2_FXF_WANT_READ_ACL) {
    access_str = pstrcat(p, access_str, *access_str ? "|" : "",
      "FXF_WANT_READ_ACL", NULL);
  }

  if (desired_access & SSH2_FXF_WANT_WRITE_ACL) {
    access_str = pstrcat(p, access_str, *access_str ? "|" : "",
      "FXF_WANT_WRITE_ACL", NULL);
  }

  if (desired_access & SSH2_FXF_WANT_WRITE_OWNER) {
    access_str = pstrcat(p, access_str, *access_str ? "|" : "",
      "FXF_WANT_WRITE_OWNER", NULL);
  }

  pr_trace_msg(trace_channel, trace_level,
    "OPEN flags = %s, desired access = %s", flags_str, access_str);
}

static int fxp_get_v5_open_flags(uint32_t desired_access, uint32_t flags) {
  uint32_t base_flag;

  /* Assume that the desired flag is read-only by default. */
  int res = O_RDONLY;

  /* These mappings are found in draft-ietf-secsh-filexfer-05.txt,
   * section 6.3.1.
   */

  if ((desired_access & SSH2_FXF_WANT_READ_DATA) ||
      (desired_access & SSH2_FXF_WANT_READ_ATTRIBUTES)) {

    if ((desired_access & SSH2_FXF_WANT_WRITE_DATA) ||
        (desired_access & SSH2_FXF_WANT_WRITE_ATTRIBUTES)) {
      res = O_RDWR;

#ifdef O_APPEND
      if ((desired_access & SSH2_FXF_WANT_APPEND_DATA) &&
          ((flags & SSH2_FXF_ACCESS_APPEND_DATA) ||
           (flags & SSH2_FXF_ACCESS_APPEND_DATA_ATOMIC))) {
        res |= O_APPEND;
      }
#endif

    } else {
      res = O_RDONLY;
    }

  } else if ((desired_access & SSH2_FXF_WANT_WRITE_DATA) ||
             (desired_access & SSH2_FXF_WANT_WRITE_ATTRIBUTES)) {
    res = O_WRONLY;

#ifdef O_APPEND
    if ((desired_access & SSH2_FXF_WANT_APPEND_DATA) &&
        ((flags & SSH2_FXF_ACCESS_APPEND_DATA) ||
         (flags & SSH2_FXF_ACCESS_APPEND_DATA_ATOMIC))) {
      res |= O_APPEND;
    }
#endif
  }

  /* The flags value, in the case of v5 (and later) OPEN requests, has
   * a "base" value, along with some modifying bits masked in.
   */
  base_flag = (flags &~ (SSH2_FXF_ACCESS_APPEND_DATA|SSH2_FXF_ACCESS_APPEND_DATA_ATOMIC|SSH2_FXF_ACCESS_TEXT_MODE));

  switch (base_flag) {
    case SSH2_FXF_CREATE_NEW:
      res |= O_CREAT|O_EXCL;
      break;

    case SSH2_FXF_CREATE_TRUNCATE:
      if (res == O_RDONLY) {
        /* A truncate is a write. */
        res = O_WRONLY;
      }
      res |= O_CREAT|O_TRUNC;
      break;

    case SSH2_FXF_OPEN_EXISTING:
      break;

    case SSH2_FXF_OPEN_OR_CREATE:
      res |= O_CREAT;
      break;

    case SSH2_FXF_TRUNCATE_EXISTING:
      if (res == O_RDONLY) {
        /* A truncate is a write. */
        res = O_WRONLY;
      }
      res |= O_TRUNC;
      break;

    default:
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "unknown OPEN base flag value (%lu), defaulting to O_RDONLY",
        (unsigned long) base_flag);
      break;
  }

  return res;
}

/* Like pr_strtime(), except that it uses pr_gmtime() rather than
 * pr_localtime().
 */
static const char *fxp_strtime(pool *p, time_t t) {
  static char buf[64];
  static char *mons[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
    "Aug", "Sep", "Oct", "Nov", "Dec" };
  static char *days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
  struct tm *tm;

  memset(buf, '\0', sizeof(buf));

  tm = pr_gmtime(p, &t);
  if (tm != NULL) {
    pr_snprintf(buf, sizeof(buf), "%s %s %2d %02d:%02d:%02d %d",
      days[tm->tm_wday], mons[tm->tm_mon], tm->tm_mday, tm->tm_hour,
      tm->tm_min, tm->tm_sec, tm->tm_year + 1900);

  } else {
    buf[0] = '\0';
  }

  buf[sizeof(buf)-1] = '\0';
  return buf;
}

static void fxp_cmd_dispatch(cmd_rec *cmd) {
  pr_cmd_dispatch_phase(cmd, POST_CMD, 0);
  pr_cmd_dispatch_phase(cmd, LOG_CMD, 0);
  pr_response_clear(&resp_list);
}

static void fxp_cmd_dispatch_err(cmd_rec *cmd) {
  pr_cmd_dispatch_phase(cmd, POST_CMD_ERR, 0);
  pr_cmd_dispatch_phase(cmd, LOG_CMD_ERR, 0);
  pr_response_clear(&resp_err_list);
}

static void fxp_cmd_note_file_status(cmd_rec *cmd, const char *status) {
  if (pr_table_add(cmd->notes, "mod_sftp.file-status",
      pstrdup(cmd->pool, status), 0) < 0) {
    if (errno != EEXIST) {
      pr_trace_msg(trace_channel, 3,
        "error stashing file status in command notes: %s", strerror(errno));
    }
  }
}

static const char *fxp_get_request_type_desc(unsigned char request_type) {
  switch (request_type) {
    case SFTP_SSH2_FXP_INIT:
      return "INIT";

    case SFTP_SSH2_FXP_VERSION:
      /* XXX We should never receive this type of message from the client. */
      return "VERSION";

    case SFTP_SSH2_FXP_OPEN:
      return "OPEN";

    case SFTP_SSH2_FXP_CLOSE:
      return "CLOSE";

    case SFTP_SSH2_FXP_READ:
      return "READ";

    case SFTP_SSH2_FXP_WRITE:
      return "WRITE";

    case SFTP_SSH2_FXP_LSTAT:
      return "LSTAT";

    case SFTP_SSH2_FXP_FSTAT:
      return "FSTAT";

    case SFTP_SSH2_FXP_SETSTAT:
      return "SETSTAT";

    case SFTP_SSH2_FXP_FSETSTAT:
      return "FSETSTAT";

    case SFTP_SSH2_FXP_OPENDIR:
      return "OPENDIR";

    case SFTP_SSH2_FXP_READDIR:
      return "READDIR";

    case SFTP_SSH2_FXP_REMOVE:
      return "REMOVE";

    case SFTP_SSH2_FXP_MKDIR:
      return "MKDIR";

    case SFTP_SSH2_FXP_RMDIR:
      return "RMDIR";

    case SFTP_SSH2_FXP_REALPATH:
      return "REALPATH";

    case SFTP_SSH2_FXP_STAT:
      return "STAT";

    case SFTP_SSH2_FXP_RENAME:
      return "RENAME";

    case SFTP_SSH2_FXP_READLINK:
      return "READLINK";

    case SFTP_SSH2_FXP_LINK:
      return "LINK";

    case SFTP_SSH2_FXP_SYMLINK:
      return "SYMLINK";

    case SFTP_SSH2_FXP_LOCK:
      return "LOCK";

    case SFTP_SSH2_FXP_UNLOCK:
      return "UNLOCK";

    case SFTP_SSH2_FXP_STATUS:
      return "STATUS";

    case SFTP_SSH2_FXP_HANDLE:
      return "HANDLE";

    case SFTP_SSH2_FXP_DATA:
      return "DATA";

    case SFTP_SSH2_FXP_NAME:
      return "NAME";

    case SFTP_SSH2_FXP_ATTRS:
      return "ATTRS";

    case SFTP_SSH2_FXP_EXTENDED:
      return "EXTENDED";

    case SFTP_SSH2_FXP_EXTENDED_REPLY:
      return "EXTENDED_REPLY";
  }

  return "(unknown)";
}

static int fxp_path_pass_regex_filters(pool *p, const char *request,
    const char *path) {
  int res;
  xaset_t *set;

  set = get_dir_ctxt(p, (char *) path);

  res = pr_filter_allow_path(set, path);
  switch (res) {
    case 0:
      break;

    case PR_FILTER_ERR_FAILS_ALLOW_FILTER:
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "path '%s' for %s denied by PathAllowFilter", path, request);
      errno = EACCES;
      return -1;

    case PR_FILTER_ERR_FAILS_DENY_FILTER:
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "path '%s' for %s denied by PathDenyFilter", path, request);
      errno = EACCES;
      return -1;
  }

  return 0;
}

/* FXP_STATUS messages */
static void fxp_status_write(pool *p, unsigned char **buf, uint32_t *buflen,
    uint32_t request_id, uint32_t status_code, const char *status_msg,
    const char *extra_data) {
  char num[32];

  /* Add a fake response to the response chain, for use by mod_log's
   * logging, e.g. for supporting the %S/%s LogFormat variables.
   */

  pr_response_clear(&resp_list);
  pr_response_clear(&resp_err_list);

  memset(num, '\0', sizeof(num));
  pr_snprintf(num, sizeof(num)-1, "%lu", (unsigned long) status_code);
  num[sizeof(num)-1] = '\0';
  pr_response_add(pstrdup(p, num), "%s", status_msg);

  sftp_msg_write_byte(buf, buflen, SFTP_SSH2_FXP_STATUS);
  sftp_msg_write_int(buf, buflen, request_id);
  sftp_msg_write_int(buf, buflen, status_code);

  if (fxp_session->client_version >= 3) {
    sftp_msg_write_string(buf, buflen, status_msg);
    /* XXX localization */
    sftp_msg_write_string(buf, buflen, "en-US");

    if (fxp_session->client_version >= 5 &&
        extra_data) {
      /* Used specifically for UNKNOWN_PRINCIPAL errors */
      sftp_msg_write_string(buf, buflen, extra_data);
    }
  }
}

/* The SFTP subsystem Draft defines a few new data types. */

#if 0
/* XXX Not really used for messages from clients. */
static uint16_t fxp_msg_read_short(pool *p, char **buf, uint32_t *buflen) {
  uint16_t val;

  (void) p;

  if (*buflen < sizeof(uint16_t)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SFTP message format error: unable to read short (buflen = %lu)",
      (unsigned long) *buflen); 
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION, NULL);
  }

  memcpy(&val, *buf, sizeof(uint16_t));
  (*buf) += sizeof(uint16_t);
  (*buflen) -= sizeof(uint16_t);

  val = ntohs(val);
  return val;
}
#endif

static struct fxp_extpair *fxp_msg_read_extpair(pool *p, unsigned char **buf,
    uint32_t *buflen) {
  uint32_t namelen, datalen;
  unsigned char *name, *data;
  struct fxp_extpair *extpair;

  namelen = sftp_msg_read_int(p, buf, buflen);
  if (*buflen < namelen) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SFTP message format error: unable to read %lu bytes of extpair name "
      "data (buflen = %lu)", (unsigned long) namelen, (unsigned long) *buflen);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION, NULL);
  }

  if (namelen > FXP_MAX_EXTENDED_ATTR_LEN) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "received too-long extended attribute name (%lu > max %lu), ignoring",
      (unsigned long) namelen, (unsigned long) FXP_MAX_EXTENDED_ATTR_LEN);
    errno = EINVAL;
    return NULL;
  }

  name = palloc(p, namelen + 1);
  memcpy(name, *buf, namelen);
  (*buf) += namelen;
  (*buflen) -= namelen;
  name[namelen] = '\0';

  datalen = sftp_msg_read_int(p, buf, buflen);
  if (datalen > 0) {
    if (datalen > FXP_MAX_EXTENDED_ATTR_LEN) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "received too-long extended attribute '%s' value (%lu > max %lu), "
        "ignoring", name, (unsigned long) datalen,
        (unsigned long) FXP_MAX_EXTENDED_ATTR_LEN);
      errno = EINVAL;
      return NULL;
    }

    data = sftp_msg_read_data(p, buf, buflen, datalen);

  } else {
    data = NULL;
  }

  extpair = palloc(p, sizeof(struct fxp_extpair));
  extpair->ext_name = (char *) name;
  extpair->ext_datalen = datalen;
  extpair->ext_data = data;

  return extpair;
}

static uint32_t fxp_msg_write_short(unsigned char **buf, uint32_t *buflen,
    uint16_t val) {
  uint32_t len = 0;

  if (*buflen < sizeof(uint16_t)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SFTP message format error: unable to write short (buflen = %lu)",
      (unsigned long) *buflen);
    SFTP_DISCONNECT_CONN(SFTP_SSH2_DISCONNECT_BY_APPLICATION, NULL);
  }

  len = sizeof(uint16_t);

  val = htons(val);
  memcpy(*buf, &val, len);
  (*buf) += len;
  (*buflen) -= len;

  return len;
}

static void fxp_msg_write_extpair(unsigned char **buf, uint32_t *buflen,
    struct fxp_extpair *extpair) {
  uint32_t len;

  len = strlen(extpair->ext_name);
  sftp_msg_write_data(buf, buflen, (unsigned char *) extpair->ext_name, len,
    TRUE);
  sftp_msg_write_data(buf, buflen, extpair->ext_data, extpair->ext_datalen,
    TRUE);
}

static uint32_t fxp_attrs_clear_unsupported(uint32_t attr_flags) {

  /* Clear any unsupported flags. */
  if (attr_flags & SSH2_FX_ATTR_ALLOCATION_SIZE) {
    pr_trace_msg(trace_channel, 17,
      "clearing unsupported ALLOCATION_SIZE attribute flag");
    attr_flags &= ~SSH2_FX_ATTR_ALLOCATION_SIZE;
  }

  if (attr_flags & SSH2_FX_ATTR_SUBSECOND_TIMES) {
    pr_trace_msg(trace_channel, 17,
      "clearing unsupported SUBSECOND_TIMES attribute flag");
    attr_flags &= ~SSH2_FX_ATTR_SUBSECOND_TIMES;
  }

  if (attr_flags & SSH2_FX_ATTR_ACL) {
    pr_trace_msg(trace_channel, 17,
      "clearing unsupported ACL attribute flag");
    attr_flags &= ~SSH2_FX_ATTR_ACL;
  }

  if (attr_flags & SSH2_FX_ATTR_BITS) {
    pr_trace_msg(trace_channel, 17,
      "clearing unsupported BITS attribute flag");
    attr_flags &= ~SSH2_FX_ATTR_BITS;
  }

  if (attr_flags & SSH2_FX_ATTR_TEXT_HINT) {
    pr_trace_msg(trace_channel, 17,
      "clearing unsupported TEXT_HINT attribute flag");
    attr_flags &= ~SSH2_FX_ATTR_TEXT_HINT;
  }

  if (attr_flags & SSH2_FX_ATTR_MIME_TYPE) {
    pr_trace_msg(trace_channel, 17,
      "clearing unsupported MIME_TYPE attribute flag");
    attr_flags &= ~SSH2_FX_ATTR_MIME_TYPE;
  }

  if (attr_flags & SSH2_FX_ATTR_UNTRANSLATED_NAME) {
    pr_trace_msg(trace_channel, 17,
      "clearing unsupported UNTRANSLATED_NAME attribute flag");
    attr_flags &= ~SSH2_FX_ATTR_UNTRANSLATED_NAME;
  }

  if (attr_flags & SSH2_FX_ATTR_CTIME) {
    pr_trace_msg(trace_channel, 17,
      "clearing unsupported CTIME attribute flag");
    attr_flags &= ~SSH2_FX_ATTR_CTIME;
  }

  return attr_flags;
}

static int fxp_attrs_set(pr_fh_t *fh, const char *path, struct stat *attrs,
    uint32_t attr_flags, array_header *xattrs, unsigned char **buf,
    uint32_t *buflen, struct fxp_packet *fxp) {
  struct stat st;
  int res;

  /* Note: path is never null; it is always passed by the caller.  fh MAY be
   * null, depending on whether the caller already has a file handle or not.
   */

  if (fh != NULL) {
    res = pr_fsio_fstat(fh, &st);

  } else {
    pr_fs_clear_cache2(path);
    res = pr_fsio_lstat(path, &st);
  }

  if (res < 0) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error checking '%s': %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, buf, buflen, fxp->request_id, status_code,
      reason, NULL);

    errno = xerrno;
    return -1;
  }

  if (attr_flags & SSH2_FX_ATTR_PERMISSIONS) {
    if (attrs->st_mode &&
        st.st_mode != attrs->st_mode) {
      cmd_rec *cmd;

      cmd = fxp_cmd_alloc(fxp->pool, "SITE_CHMOD", pstrdup(fxp->pool, path));
      if (!dir_check(fxp->pool, cmd, G_WRITE, (char *) path, NULL)) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "chmod of '%s' blocked by <Limit> configuration", path);

        errno = EACCES;
        res = -1;

      } else {
        if (fh != NULL) {
          res = pr_fsio_fchmod(fh, attrs->st_mode);

        } else {
          res = pr_fsio_chmod(path, attrs->st_mode);
        }
      }

      if (res < 0) {
        uint32_t status_code;
        const char *reason;
        int xerrno = errno;

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error changing permissions of '%s' to 0%o: %s", path,
          (unsigned int) attrs->st_mode, strerror(xerrno));

        status_code = fxp_errno2status(xerrno, &reason);

        pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
          "('%s' [%d])", (unsigned long) status_code, reason,
          xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

        fxp_status_write(fxp->pool, buf, buflen, fxp->request_id, status_code,
          reason, NULL);

        errno = xerrno;
        return -1;
      }

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client set permissions on '%s' to 0%o", path,
        (unsigned int) (attrs->st_mode & ~S_IFMT));
    }
  }

  if ((attr_flags & SSH2_FX_ATTR_UIDGID) ||
      (attr_flags & SSH2_FX_ATTR_OWNERGROUP)) {
    int do_chown = FALSE;
    uid_t client_uid = (uid_t) -1;
    gid_t client_gid = (gid_t) -1;

    if (st.st_uid != attrs->st_uid) {
      client_uid = attrs->st_uid;
      do_chown = TRUE;
    }

    if (st.st_gid != attrs->st_gid) {
      client_gid = attrs->st_gid;
      do_chown = TRUE;
    }

    if (do_chown) {
      cmd_rec *cmd;

      cmd = fxp_cmd_alloc(fxp->pool, "SITE_CHGRP", pstrdup(fxp->pool, path));
      if (!dir_check(fxp->pool, cmd, G_WRITE, (char *) path, NULL)) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "chown of '%s' blocked by <Limit> configuration", path);

        errno = EACCES;
        res = -1;

      } else {
        if (fh != NULL) {
          res = pr_fsio_fchown(fh, client_uid, client_gid);

        } else {
          res = pr_fsio_chown(path, client_uid, client_gid);
        }
      }

      if (res < 0) {
        uint32_t status_code;
        const char *reason;
        int xerrno = errno;

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error changing ownership of '%s' to UID %s, GID %s: %s",
          path, pr_uid2str(fxp->pool, client_uid),
          pr_gid2str(fxp->pool, client_gid), strerror(xerrno));

        status_code = fxp_errno2status(xerrno, &reason);

        pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
          "('%s' [%d])", (unsigned long) status_code, reason,
          xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

        fxp_status_write(fxp->pool, buf, buflen, fxp->request_id, status_code,
          reason, NULL);

        errno = xerrno;
        return -1;
      }

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client set ownership of '%s' to UID %s, GID %s",
        path, pr_uid2str(fxp->pool, client_uid),
        pr_gid2str(fxp->pool, client_gid));
    }
  }

  if (attr_flags & SSH2_FX_ATTR_SIZE) {
    if (attrs->st_size &&
        st.st_size != attrs->st_size) {

      /* If we're dealing with a FIFO, just pretend that the truncate(2)
       * succeeded; FIFOs don't handle truncation well.  And it won't
       * necessarily matter to the client, right?
       */
      if (S_ISREG(st.st_mode)) {
        if (fh != NULL) {
          res = pr_fsio_ftruncate(fh, attrs->st_size);

        } else {
          res = pr_fsio_truncate(path, attrs->st_size);
        }

      } else {
        res = 0;
      }

      if (res < 0) {
        uint32_t status_code;
        const char *reason;
        int xerrno = errno;

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error changing size of '%s' from %" PR_LU " bytes to %" PR_LU
          " bytes: %s", path, (pr_off_t) st.st_size, (pr_off_t) attrs->st_size,
          strerror(xerrno));

        status_code = fxp_errno2status(xerrno, &reason);

        pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
          "('%s' [%d])", (unsigned long) status_code, reason,
          xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

        fxp_status_write(fxp->pool, buf, buflen, fxp->request_id, status_code,
          reason, NULL);

        errno = xerrno;
        return -1;
      }

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client set size of '%s' to %" PR_LU " bytes", path,
        (pr_off_t) attrs->st_size);
    }
  }

  if (fxp_session->client_version <= 3 &&
      attr_flags & SSH2_FX_ATTR_ACMODTIME) {
    if (st.st_atime != attrs->st_atime ||
        st.st_mtime != attrs->st_mtime) {
      struct timeval tvs[2];

      tvs[0].tv_sec = attrs->st_atime;
      tvs[0].tv_usec = 0;

      tvs[1].tv_sec = attrs->st_mtime;
      tvs[1].tv_usec = 0;

      if (fh != NULL) {
        res = pr_fsio_futimes(fh, tvs);

      } else {
        res = pr_fsio_utimes(path, tvs);
      }

      if (res < 0) {
        uint32_t status_code;
        const char *reason;
        int xerrno = errno;

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error changing access/modification times '%s': %s", path,
           strerror(xerrno));

        status_code = fxp_errno2status(xerrno, &reason);

        pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
          "('%s' [%d])", (unsigned long) status_code, reason,
          xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

        fxp_status_write(fxp->pool, buf, buflen, fxp->request_id, status_code,
          reason, NULL);

        errno = xerrno;
        return -1;
      }

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client set access time of '%s' to %s, modification time to %s",
        path, fxp_strtime(fxp->pool, attrs->st_atime),
        fxp_strtime(fxp->pool, attrs->st_mtime));
    }
  }

  if (fxp_session->client_version > 3) {
    /* Note: we handle the xattrs FIRST, before the timestamps, so that
     * setting the xattrs does not change the expected timestamps, thus
     * preserving the principle of least surprise.
     */
    if (attr_flags & SSH2_FX_ATTR_EXTENDED) {
#ifdef PR_USE_XATTR
      if (xattrs != NULL &&
          xattrs->nelts > 0) {
        register unsigned int i;
        struct fxp_extpair **ext_pairs;

        ext_pairs = xattrs->elts;
        for (i = 0; i < xattrs->nelts; i++) {
          struct fxp_extpair *xattr;
          const char *xattr_name;
          void *xattr_val;
          size_t xattr_valsz;

          xattr = ext_pairs[i];
          xattr_name = xattr->ext_name;
          xattr_val = xattr->ext_data;
          xattr_valsz = (size_t) xattr->ext_datalen;

          if (fh != NULL) {
            res = pr_fsio_fsetxattr(fxp->pool, fh, xattr_name, xattr_val,
              xattr_valsz, 0);

          } else {
            res = pr_fsio_lsetxattr(fxp->pool, path, xattr_name, xattr_val,
              xattr_valsz, 0);
          }

          if (res < 0) {
            uint32_t status_code;
            const char *reason;
            int xerrno = errno;

            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
              "error setting xattr '%s' (%lu bytes) on '%s': %s", xattr_name,
              (unsigned long) xattr_valsz, path, strerror(xerrno));

            status_code = fxp_errno2status(xerrno, &reason);

            pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
              "('%s' [%d])", (unsigned long) status_code, reason,
              strerror(xerrno), xerrno);

            fxp_status_write(fxp->pool, buf, buflen, fxp->request_id,
              status_code, reason, NULL);

            errno = xerrno;
            return -1;
          }
        }
      }
#else
      (void) xattrs;
#endif /* PR_USE_XATTR */
    }

    if (attr_flags & SSH2_FX_ATTR_ACCESSTIME) {
      if (st.st_atime != attrs->st_atime) {
        struct timeval tvs[2];

        tvs[0].tv_sec = attrs->st_atime;
        tvs[0].tv_usec = 0;

        tvs[1].tv_sec = st.st_mtime;
        tvs[1].tv_usec = 0;

        if (fh != NULL) {
          res = pr_fsio_futimes(fh, tvs);

        } else {
          res = pr_fsio_utimes(path, tvs);
        }

        if (res < 0) {
          uint32_t status_code;
          const char *reason;
          int xerrno = errno;

          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error changing access time '%s': %s", path, strerror(xerrno));

          status_code = fxp_errno2status(xerrno, &reason);
  
          pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
            "('%s' [%d])", (unsigned long) status_code, reason,
            xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

          fxp_status_write(fxp->pool, buf, buflen, fxp->request_id, status_code,
            reason, NULL);

          errno = xerrno;
          return -1;
        }

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "client set access time of '%s' to %s", path,
          fxp_strtime(fxp->pool, attrs->st_atime));
      }
    }

    if (attr_flags & SSH2_FX_ATTR_MODIFYTIME) {
      if (st.st_mtime != attrs->st_mtime) {
        struct timeval tvs[2];

        tvs[0].tv_sec = st.st_atime;
        tvs[0].tv_usec = 0;

        tvs[1].tv_sec = attrs->st_mtime;
        tvs[1].tv_usec = 0;

        if (fh != NULL) {
          res = pr_fsio_futimes(fh, tvs);

        } else {
          res = pr_fsio_utimes(path, tvs);
        }

        if (res < 0) {
          uint32_t status_code;
          const char *reason;
          int xerrno = errno;

          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error changing modification time '%s': %s", path,
            strerror(xerrno));

          status_code = fxp_errno2status(xerrno, &reason);

          pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
            "('%s' [%d])", (unsigned long) status_code, reason,
            xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

          fxp_status_write(fxp->pool, buf, buflen, fxp->request_id, status_code,
            reason, NULL);

          errno = xerrno;
          return -1;
        }

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "client set modification time of '%s' to %s", path,
          fxp_strtime(fxp->pool, attrs->st_mtime));
      }
    }
  }

  return 0;
}

/* Provide a stringified representation of attributes sent by clients. */

static const char *fxp_strftype(mode_t mode) {
  if (S_ISREG(mode)) {
    return "file";
  }

  if (S_ISDIR(mode)) {
    return "dir";
  }

  if (S_ISLNK(mode)) {
    return "symlink";
  }

  if (S_ISSOCK(mode)) {
    return "socket";
  }

#ifdef S_ISFIFO
  if (S_ISFIFO(mode)) {
    return "fifo";
  }
#endif

#ifdef S_ISCHR
  if (S_ISCHR(mode)) {
    return "dev/char";
  }
#endif

#ifdef S_ISBLK
  if (S_ISBLK(mode)) {
    return "dev/block";
  }
#endif

  return "unknown";
}

static char *fxp_strattrs(pool *p, struct stat *st, uint32_t *attr_flags) {
  char buf[PR_TUNABLE_BUFFER_SIZE], *ptr;
  size_t buflen = 0, bufsz;
  uint32_t flags = 0;

  buflen = 0;
  bufsz = sizeof(buf);
  memset(buf, '\0', bufsz);

  ptr = buf;

  if (attr_flags != NULL) {
    flags = *attr_flags;

  } else {
    if (fxp_session->client_version <= 3) {
      flags = SSH2_FX_ATTR_SIZE|SSH2_FX_ATTR_UIDGID|SSH2_FX_ATTR_PERMISSIONS|
        SSH2_FX_ATTR_ACMODTIME;

    } else {
      flags = SSH2_FX_ATTR_SIZE|SSH2_FX_ATTR_PERMISSIONS|
        SSH2_FX_ATTR_ACCESSTIME|SSH2_FX_ATTR_MODIFYTIME|
        SSH2_FX_ATTR_OWNERGROUP;

      if (fxp_session->client_version >= 6) {
        flags |= SSH2_FX_ATTR_LINK_COUNT;
#ifdef PR_USE_XATTR
        flags |= SSH2_FX_ATTR_EXTENDED;
#endif /* PR_USE_XATTR */
      }
    }
  }

  pr_snprintf(ptr, bufsz - buflen, "type=%s;", fxp_strftype(st->st_mode));
  buflen = strlen(buf);
  ptr = buf + buflen;

  if (flags & SSH2_FX_ATTR_SIZE) {
    pr_snprintf(ptr, bufsz - buflen, "size=%" PR_LU ";",
      (pr_off_t) st->st_size);
    buflen = strlen(buf);
    ptr = buf + buflen;
  }

  if ((flags & SSH2_FX_ATTR_UIDGID) ||
      (flags & SSH2_FX_ATTR_OWNERGROUP)) {
    pr_snprintf(ptr, bufsz - buflen, "UNIX.owner=%s;",
      pr_uid2str(NULL, st->st_uid));
    buflen = strlen(buf);
    ptr = buf + buflen;

    pr_snprintf(ptr, bufsz - buflen, "UNIX.group=%s;",
      pr_gid2str(NULL, st->st_gid));
    buflen = strlen(buf);
    ptr = buf + buflen;
  }

  if (flags & SSH2_FX_ATTR_PERMISSIONS) {
    pr_snprintf(ptr, bufsz - buflen, "UNIX.mode=%04o;",
      (unsigned int) st->st_mode & 07777);
    buflen = strlen(buf);
    ptr = buf + buflen;
  }

  if (fxp_session->client_version <= 3) {
    if (flags & SSH2_FX_ATTR_ACMODTIME) {
      struct tm *tm;

      tm = pr_gmtime(p, (const time_t *) &st->st_atime);
      if (tm != NULL) {
        pr_snprintf(ptr, bufsz - buflen, "access=%04d%02d%02d%02d%02d%02d;",
          tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min,
          tm->tm_sec);
        buflen = strlen(buf);
        ptr = buf + buflen;

      } else {
        pr_trace_msg(trace_channel, 1,
          "error obtaining st_atime GMT timestamp: %s", strerror(errno));
      }

      tm = pr_gmtime(p, (const time_t *) &st->st_mtime);
      if (tm != NULL) {
        pr_snprintf(ptr, bufsz - buflen, "modify=%04d%02d%02d%02d%02d%02d;",
          tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min,
          tm->tm_sec);

      } else {
        pr_trace_msg(trace_channel, 1,
          "error obtaining st_mtime GMT timestamp: %s", strerror(errno));
      }

      buflen = strlen(buf);
      ptr = buf + buflen;
    }

  } else { 
    if (flags & SSH2_FX_ATTR_ACCESSTIME) {
      struct tm *tm;

      tm = pr_gmtime(p, (const time_t *) &st->st_atime);
      if (tm != NULL) {
        pr_snprintf(ptr, bufsz - buflen, "access=%04d%02d%02d%02d%02d%02d;",
          tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min,
          tm->tm_sec);

      } else {
        pr_trace_msg(trace_channel, 1,
          "error obtaining st_atime GMT timestamp: %s", strerror(errno));
      }

      buflen = strlen(buf);
      ptr = buf + buflen;
    }

    if (flags & SSH2_FX_ATTR_MODIFYTIME) {
      struct tm *tm;

      tm = pr_gmtime(p, (const time_t *) &st->st_mtime);
      if (tm != NULL) {
        pr_snprintf(ptr, bufsz - buflen, "modify=%04d%02d%02d%02d%02d%02d;",
          tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min,
          tm->tm_sec);

      } else {
        pr_trace_msg(trace_channel, 1,
          "error obtaining st_mtime GMT timestamp: %s", strerror(errno));
      }

      buflen = strlen(buf);
      ptr = buf + buflen;
    }

    if (flags & SSH2_FX_ATTR_LINK_COUNT) {
      pr_snprintf(ptr, bufsz - buflen, "UNIX.nlink=%lu;",
        (unsigned long) st->st_nlink);
      buflen = strlen(buf);
      ptr = buf + buflen;
    }
  }

  return pstrdup(p, buf);
}

static char *fxp_strattrflags(pool *p, uint32_t flags) {
  char *str = "";

  if (flags & SSH2_FX_ATTR_SIZE) {
    str = pstrcat(p, str, *str ? ";" : "", "size", NULL);
  }

  if ((flags & SSH2_FX_ATTR_UIDGID) ||
      (flags & SSH2_FX_ATTR_OWNERGROUP)) {
    str = pstrcat(p, str, *str ? ";" : "", "UNIX.owner", NULL);
    str = pstrcat(p, str, *str ? ";" : "", "UNIX.group", NULL);
  }

  if (flags & SSH2_FX_ATTR_PERMISSIONS) {
    str = pstrcat(p, str, *str ? ";" : "", "UNIX.mode", NULL);
  }

  if (fxp_session->client_version <= 3) {
    if (flags & SSH2_FX_ATTR_ACMODTIME) {
      str = pstrcat(p, str, *str ? ";" : "", "access", NULL);
      str = pstrcat(p, str, *str ? ";" : "", "modify", NULL);
    }

  } else {
    if (flags & SSH2_FX_ATTR_ACCESSTIME) {
      str = pstrcat(p, str, *str ? ";" : "", "access", NULL);
    }

    if (flags & SSH2_FX_ATTR_MODIFYTIME) {
      str = pstrcat(p, str, *str ? ";" : "", "modify", NULL);
    }
  }

  return str;
}

static char *fxp_stroflags(pool *p, int flags) {
  char *str = "";

  if (flags == O_RDONLY) {
    str = pstrcat(p, str, "O_RDONLY", NULL);

  } else if (flags & O_RDWR) {
    str = pstrcat(p, str, "O_RDWR", NULL);

  } else if (flags & O_WRONLY) {
    str = pstrcat(p, str, "O_WRONLY", NULL);
  }

#ifdef O_APPEND
  if (flags & O_APPEND) {
    str = pstrcat(p, str, *str ? "|" : "", "O_APPEND", NULL);
  }
#endif

  if (flags & O_CREAT) {
    str = pstrcat(p, str, *str ? "|" : "", "O_CREAT", NULL);
  }

  if (flags & O_TRUNC) {
    str = pstrcat(p, str, *str ? "|" : "", "O_TRUNC", NULL);
  }

  if (flags & O_EXCL) {
    str = pstrcat(p, str, *str ? "|" : "", "O_EXCL", NULL);
  }

  return str;
}

static array_header *fxp_xattrs_read(pool *p, unsigned char **buf,
    uint32_t *buflen) {
  register unsigned int i;
  uint32_t extpair_count;
  array_header *xattrs = NULL;

  extpair_count = sftp_msg_read_int(p, buf, buflen);
  pr_trace_msg(trace_channel, 15,
    "protocol version %lu: read EXTENDED attribute: %lu extensions",
    (unsigned long) fxp_session->client_version,
    (unsigned long) extpair_count);

  if (extpair_count > FXP_MAX_EXTENDED_ATTRIBUTES) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "received too many EXTENDED attributes (%lu > max %lu), "
      "truncating to max", (unsigned long) extpair_count,
      (unsigned long) FXP_MAX_EXTENDED_ATTRIBUTES);
    extpair_count = FXP_MAX_EXTENDED_ATTRIBUTES;
  }

  xattrs = make_array(p, 1, sizeof(struct fxp_extpair *));

  for (i = 0; i < extpair_count; i++) {
    struct fxp_extpair *ext;

    ext = fxp_msg_read_extpair(p, buf, buflen);
    if (ext != NULL) {
      pr_trace_msg(trace_channel, 15,
        "protocol version %lu: read EXTENDED attribute: "
        "extension '%s' (%lu bytes of data)",
        (unsigned long) fxp_session->client_version, ext->ext_name,
        (unsigned long) ext->ext_datalen);

      *((struct fxp_extpair **) push_array(xattrs)) = ext;
    }
  }

  return xattrs;
}

static struct stat *fxp_attrs_read(struct fxp_packet *fxp, unsigned char **buf,
    uint32_t *buflen, uint32_t *flags, array_header **xattrs) {
  struct stat *st;

  st = pcalloc(fxp->pool, sizeof(struct stat));

  *flags = sftp_msg_read_int(fxp->pool, buf, buflen);

  if (fxp_session->client_version <= 3) {
    if (*flags & SSH2_FX_ATTR_SIZE) {
      st->st_size = sftp_msg_read_long(fxp->pool, buf, buflen);
    }

    if (*flags & SSH2_FX_ATTR_UIDGID) {
      st->st_uid = sftp_msg_read_int(fxp->pool, buf, buflen);
      st->st_gid = sftp_msg_read_int(fxp->pool, buf, buflen);
    }

    if (*flags & SSH2_FX_ATTR_PERMISSIONS) {
      st->st_mode |= sftp_msg_read_int(fxp->pool, buf, buflen);
    }

    if (*flags & SSH2_FX_ATTR_ACMODTIME) {
      st->st_atime = sftp_msg_read_int(fxp->pool, buf, buflen);
      st->st_mtime = sftp_msg_read_int(fxp->pool, buf, buflen);
    }

  } else {
    char file_type;

    /* XXX Use this to create different types of files?  E.g. what if the client
     * wants to OPEN a socket, or a fifo?
     */
    file_type = sftp_msg_read_byte(fxp->pool, buf, buflen);
    switch (file_type) {
      case SSH2_FX_ATTR_FTYPE_REGULAR:
        st->st_mode |= S_IFREG;
        break;

      case SSH2_FX_ATTR_FTYPE_DIRECTORY:
        st->st_mode |= S_IFDIR;
        break;

      case SSH2_FX_ATTR_FTYPE_SYMLINK:
        st->st_mode |= S_IFLNK;
        break;

      case SSH2_FX_ATTR_FTYPE_SPECIAL:
        /* Default to marking this as a character special device, rather than
         * block special.
         */
        st->st_mode |= S_IFCHR;
        break;

      case SSH2_FX_ATTR_FTYPE_UNKNOWN:
        /* Nothing to do here; leave st->st_mode alone. */
        break;

      case SSH2_FX_ATTR_FTYPE_SOCKET:
        st->st_mode |= S_IFSOCK;
        break;

      case SSH2_FX_ATTR_FTYPE_CHAR_DEVICE:
        st->st_mode |= S_IFCHR;
        break;

      case SSH2_FX_ATTR_FTYPE_BLOCK_DEVICE:
        st->st_mode |= S_IFBLK;
        break;

#ifdef S_IFIFO
      case SSH2_FX_ATTR_FTYPE_FIFO:
        st->st_mode |= S_IFIFO;
        break;
#endif /* S_IFIFO */

      default: 
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "unrecognized file type %d requested (protocol version %d)",
          file_type, fxp_session->client_version);
    }

    if (*flags & SSH2_FX_ATTR_SIZE) {
      st->st_size = sftp_msg_read_long(fxp->pool, buf, buflen);
    }

    if (*flags & SSH2_FX_ATTR_ALLOCATION_SIZE) {
      /* Read (and ignore) any allocation size attribute. */
      uint64_t allosz;

      allosz = sftp_msg_read_long(fxp->pool, buf, buflen);
      pr_trace_msg(trace_channel, 15,
        "protocol version %lu: read ALLOCATION_SIZE attribute: %" PR_LU,
        (unsigned long) fxp_session->client_version, (pr_off_t) allosz);
    }

    if (*flags & SSH2_FX_ATTR_OWNERGROUP) {
      char *name;
      uid_t uid;
      gid_t gid;

      name = sftp_msg_read_string(fxp->pool, buf, buflen);
      uid = pr_auth_name2uid(fxp->pool, name);
      if (uid == (uid_t) -1) {
        unsigned char *buf2, *ptr2;
        uint32_t buflen2, bufsz2, status_code;
        struct fxp_packet *resp;

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "unable to translate user name '%s' to UID, UNKNOWN_PRINCIPAL error",
          name);

        buflen2 = bufsz2 = FXP_RESPONSE_DATA_DEFAULT_SZ;
        buf2 = ptr2 = palloc(fxp->pool, bufsz2);

        status_code = SSH2_FX_UNKNOWN_PRINCIPAL;

        pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
          (unsigned long) status_code, fxp_strerror(status_code));

        fxp_status_write(fxp->pool, &buf2, &buflen2, fxp->request_id,
          status_code, fxp_strerror(status_code), name);

        resp = fxp_packet_create(fxp->pool, fxp->channel_id);
        resp->payload = ptr2;
        resp->payload_sz = (bufsz2 - buflen2);

        if (fxp_packet_write(resp) < 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error sending UNKNOWN_PRINCIPAL status: %s", strerror(errno));
        }

        return NULL;
      }

      st->st_uid = uid;

      name = sftp_msg_read_string(fxp->pool, buf, buflen);
      gid = pr_auth_name2gid(fxp->pool, name);
      if (gid == (gid_t) -1) {
        unsigned char *buf2, *ptr2;
        uint32_t buflen2, bufsz2, status_code;
        struct fxp_packet *resp;

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "unable to translate group name '%s' to GID, UNKNOWN_PRINCIPAL error",
          name);

        buflen2 = bufsz2 = FXP_RESPONSE_DATA_DEFAULT_SZ;
        buf2 = ptr2 = palloc(fxp->pool, bufsz2);

        status_code = SSH2_FX_UNKNOWN_PRINCIPAL;

        pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
          (unsigned long) status_code, fxp_strerror(status_code));

        fxp_status_write(fxp->pool, &buf2, &buflen2, fxp->request_id,
          status_code, fxp_strerror(status_code), name);

        resp = fxp_packet_create(fxp->pool, fxp->channel_id);
        resp->payload = ptr2;
        resp->payload_sz = (bufsz2 - buflen2);

        if (fxp_packet_write(resp) < 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error sending UNKNOWN_PRINCIPAL status: %s", strerror(errno));
        }

        return NULL;
      }

      st->st_gid = gid;
    }

    if (*flags & SSH2_FX_ATTR_PERMISSIONS) {
      st->st_mode |= sftp_msg_read_int(fxp->pool, buf, buflen);
    }

    if (*flags & SSH2_FX_ATTR_ACCESSTIME) {
      st->st_atime = sftp_msg_read_long(fxp->pool, buf, buflen);

      if (*flags & SSH2_FX_ATTR_SUBSECOND_TIMES) {
        /* Read (and ignore) the nanoseconds field. */
        uint32_t nanosecs;

        nanosecs = sftp_msg_read_int(fxp->pool, buf, buflen);
        pr_trace_msg(trace_channel, 15,
          "protocol version %lu: read ACCESSTIME SUBSECOND attribute: %lu",
          (unsigned long) fxp_session->client_version,
          (unsigned long) nanosecs);
      }
    }

    if (*flags & SSH2_FX_ATTR_CREATETIME) {
      /* Read (and ignore) the create time attribute. */
      uint64_t create_time;

      create_time = sftp_msg_read_long(fxp->pool, buf, buflen);
      pr_trace_msg(trace_channel, 15,
        "protocol version %lu: read CREATETIME attribute: %" PR_LU,
        (unsigned long) fxp_session->client_version, (pr_off_t) create_time);

      if (*flags & SSH2_FX_ATTR_SUBSECOND_TIMES) {
        /* Read (and ignore) the nanoseconds field. */
        uint32_t nanosecs;

        nanosecs = sftp_msg_read_int(fxp->pool, buf, buflen);
        pr_trace_msg(trace_channel, 15,
          "protocol version %lu: read CREATETIME SUBSECOND attribute: %lu",
          (unsigned long) fxp_session->client_version,
          (unsigned long) nanosecs);
      }
    }

    if (*flags & SSH2_FX_ATTR_MODIFYTIME) {
      st->st_mtime = sftp_msg_read_long(fxp->pool, buf, buflen);

      if (*flags & SSH2_FX_ATTR_SUBSECOND_TIMES) {
        /* Read (and ignore) the nanoseconds field. */
        uint32_t nanosecs;

        nanosecs = sftp_msg_read_int(fxp->pool, buf, buflen);
        pr_trace_msg(trace_channel, 15,
          "protocol version %lu: read MOTIFYTIME SUBSECOND attribute: %lu",
          (unsigned long) fxp_session->client_version,
          (unsigned long) nanosecs);
      }
    }

    if (*flags & SSH2_FX_ATTR_CTIME) {
      /* Read (and ignore) the ctime attribute. */
      uint64_t change_time;

      change_time = sftp_msg_read_long(fxp->pool, buf, buflen);
      pr_trace_msg(trace_channel, 15,
        "protocol version %lu: read CTIME attribute: %" PR_LU,
        (unsigned long) fxp_session->client_version, (pr_off_t) change_time);

      if (*flags & SSH2_FX_ATTR_SUBSECOND_TIMES) {
        /* Read (and ignore) the nanoseconds field. */
        uint32_t nanosecs;

        nanosecs = sftp_msg_read_int(fxp->pool, buf, buflen);
        pr_trace_msg(trace_channel, 15,
          "protocol version %lu: read CTIME SUBSECOND attribute: %lu",
          (unsigned long) fxp_session->client_version,
          (unsigned long) nanosecs);
      }
    }

    if (*flags & SSH2_FX_ATTR_ACL) {
      /* Read (and ignore) the ACL attribute. */
      char *acl;

      acl = sftp_msg_read_string(fxp->pool, buf, buflen);
      pr_trace_msg(trace_channel, 15,
        "protocol version %lu: read ACL attribute: '%s'",
        (unsigned long) fxp_session->client_version, acl ? acl : "(nil)");
    }

    if (*flags & SSH2_FX_ATTR_BITS) {
      /* Read (and ignore) the BITS attributes. */
      uint32_t attr_bits, attr_valid_bits;

      attr_bits = sftp_msg_read_int(fxp->pool, buf, buflen);
      attr_valid_bits = sftp_msg_read_int(fxp->pool, buf, buflen);

      fxp_trace_v5_bit_flags(fxp->pool, attr_bits, attr_valid_bits);
    }

    if (*flags & SSH2_FX_ATTR_TEXT_HINT) {
      /* Read (and ignore) the TEXT_HINT attribute. */
      char hint, *hint_type;

      hint = sftp_msg_read_byte(fxp->pool, buf, buflen);
      switch (hint) {
        case SSH2_FX_ATTR_KNOWN_TEXT:
          hint_type = "KNOWN_TEXT";
          break;

        case SSH2_FX_ATTR_GUESSED_TEXT:
          hint_type = "GUESSED_TEXT";
          break;

        case SSH2_FX_ATTR_KNOWN_BINARY:
          hint_type = "KNOWN_BINARY";
          break;

        case SSH2_FX_ATTR_GUESSED_BINARY:
          hint_type = "GUESSED_BINARY";
          break;

        default:
          hint_type = "(unknown)";
          break;
      }

      pr_trace_msg(trace_channel, 15,
        "protocol version %lu: read TEXT_HINT attribute: '%s'",
        (unsigned long) fxp_session->client_version, hint_type);
    }

    if (*flags & SSH2_FX_ATTR_MIME_TYPE) {
      /* Read (and ignore) the MIME_TYPE attribute. */
      char *mime_type;

      mime_type = sftp_msg_read_string(fxp->pool, buf, buflen);
      pr_trace_msg(trace_channel, 15,
        "protocol version %lu: read MIME_TYPE attribute: '%s'",
        (unsigned long) fxp_session->client_version,
        mime_type ? mime_type : "(nil)");
    }

    if (*flags & SSH2_FX_ATTR_LINK_COUNT) {
      /* Read (and ignore) the LINK_COUNT attribute. */
      uint32_t link_count;

      link_count = sftp_msg_read_int(fxp->pool, buf, buflen);
      pr_trace_msg(trace_channel, 15,
        "protocol version %lu: read LINK_COUNT attribute: %lu",
        (unsigned long) fxp_session->client_version,
        (unsigned long) link_count);
    }

    if (*flags & SSH2_FX_ATTR_UNTRANSLATED_NAME) {
      /* Read (and ignore) the UNTRANSLATED_NAME attribute. */
      char *untranslated;

      untranslated = sftp_msg_read_string(fxp->pool, buf, buflen);
      pr_trace_msg(trace_channel, 15,
        "protocol version %lu: read UNTRANSLATED_NAME attribute: '%s'",
        (unsigned long) fxp_session->client_version,
        untranslated ? untranslated : "(nil)");
    }
  }

  if (*flags & SSH2_FX_ATTR_EXTENDED) {
    array_header *ext_attrs;

    /* Read the EXTENDED attribute. */
    ext_attrs = fxp_xattrs_read(fxp->pool, buf, buflen);
    if (xattrs != NULL) {
      *xattrs = ext_attrs;
    }
  }

  return st;
}

static char fxp_get_file_type(mode_t mode) {
  if (S_ISREG(mode)) {
    return SSH2_FX_ATTR_FTYPE_REGULAR;
  }

  if (S_ISDIR(mode)) {
    return SSH2_FX_ATTR_FTYPE_DIRECTORY;
  }

  if (S_ISLNK(mode)) {
    return SSH2_FX_ATTR_FTYPE_SYMLINK;
  }

  if (S_ISSOCK(mode)) {
    if (fxp_session->client_version <= 4) {
      return SSH2_FX_ATTR_FTYPE_SPECIAL;
    }

    return SSH2_FX_ATTR_FTYPE_SOCKET;
  }

#ifdef S_ISFIFO
  if (S_ISFIFO(mode)) {
    if (fxp_session->client_version <= 4) {
      return SSH2_FX_ATTR_FTYPE_SPECIAL;
    }

    return SSH2_FX_ATTR_FTYPE_FIFO;
  }
#endif

#ifdef S_ISCHR
  if (S_ISCHR(mode)) {
    if (fxp_session->client_version <= 4) {
      return SSH2_FX_ATTR_FTYPE_SPECIAL;
    }

    return SSH2_FX_ATTR_FTYPE_CHAR_DEVICE;
  }
#endif

#ifdef S_ISBLK
  if (S_ISBLK(mode)) {
    if (fxp_session->client_version <= 4) {
      return SSH2_FX_ATTR_FTYPE_SPECIAL;
    }

    return SSH2_FX_ATTR_FTYPE_BLOCK_DEVICE;
  }
#endif

  return SSH2_FX_ATTR_FTYPE_UNKNOWN;
}

static uint32_t fxp_xattrs_write(pool *p, struct fxp_buffer *fxb,
    const char *path) {
  uint32_t len = 0;

#ifdef PR_USE_XATTR
  int res;
  array_header *names = NULL;

  res = pr_fsio_llistxattr(p, path, &names);
  if (res > 0) {
    register unsigned int i;
    pool *sub_pool;
    uint32_t xattrsz = 0;
    array_header *vals;

    sub_pool = make_sub_pool(p);
    pr_pool_tag(sub_pool, "listxattr pool");

    vals = make_array(sub_pool, names->nelts, sizeof(pr_buffer_t *));
    xattrsz = sizeof(uint32_t);

    for (i = 0; i < names->nelts; i++) {
      const char *name;
      pr_buffer_t *val;
      ssize_t valsz;

      name = ((const char **) names->elts)[i];
      xattrsz += (sizeof(uint32_t) + strlen(name));

      val = pcalloc(sub_pool, sizeof(pr_buffer_t));

      valsz = pr_fsio_lgetxattr(p, path, name, NULL, 0);
      if (valsz > 0) {
        xattrsz += (sizeof(uint32_t) + valsz);

        val->buflen = valsz;
        val->buf = palloc(sub_pool, valsz);

        valsz = pr_fsio_lgetxattr(p, path, name, val->buf, valsz);
        if (valsz > 0) {
          *((pr_buffer_t **) push_array(vals)) = val;
        }
      } else {
        /* Push the empty buffer into the list, so that the vals list
         * lines up with the names list.
         */
        *((pr_buffer_t **) push_array(vals)) = val;
      }
    }

    if (fxb->buflen < xattrsz) {
      unsigned char *ptr;
      uint32_t bufsz, resp_len;

      resp_len = fxb->bufsz - fxb->buflen;

      /* Allocate a buffer large enough for the xattrs */
      pr_trace_msg(trace_channel, 3,
        "allocating larger response buffer (have %lu bytes, need %lu bytes)",
        (unsigned long) fxb->bufsz, (unsigned long) fxb->bufsz + xattrsz);

      bufsz = fxb->bufsz + xattrsz;
      ptr = palloc(p, bufsz);

      /* Copy over our existing response data into the new buffer. */
      memcpy(ptr, fxb->ptr, resp_len);
      fxb->ptr = ptr;
      fxb->bufsz = bufsz;
      fxb->buf = ptr + resp_len;
      fxb->buflen = bufsz - resp_len;
    }

    len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), names->nelts);
    for (i = 0; i < names->nelts; i++) {
      const char *name;
      pr_buffer_t *val;

      name = ((const char **) names->elts)[i];
      val = ((pr_buffer_t **) vals->elts)[i];

      len += sftp_msg_write_string(&(fxb->buf), &(fxb->buflen), name);
      len += sftp_msg_write_data(&(fxb->buf), &(fxb->buflen),
        (const unsigned char *) val->buf, (size_t) val->buflen, TRUE);
    }

    destroy_pool(sub_pool);

  } else {
    /* Have to write an extended count of zero. */
    len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), 0);
  }
#endif /* PR_USE_XATTR */

  return len;
}

static uint32_t fxp_attrs_write(pool *p, struct fxp_buffer *fxb,
    const char *path, struct stat *st, uint32_t flags,
    const char *user_owner, const char *group_owner) {
  uint32_t len = 0;
  mode_t perms;

  if (fxp_session->client_version <= 3) {
    perms = st->st_mode;

    len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), flags);

    if (flags & SSH2_FX_ATTR_SIZE) {
      len += sftp_msg_write_long(&(fxb->buf), &(fxb->buflen), st->st_size);
    }

    if (flags & SSH2_FX_ATTR_UIDGID) {
      len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), st->st_uid);
      len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), st->st_gid);
    }

    if (flags & SSH2_FX_ATTR_PERMISSIONS) {
      len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), perms);
    }

    if (flags & SSH2_FX_ATTR_ACMODTIME) {
      len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), st->st_atime);
      len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), st->st_mtime);
    }

    if (flags & SSH2_FX_ATTR_EXTENDED) {
      len += fxp_xattrs_write(p, fxb, path);
    }

  } else {
    char file_type;

    perms = st->st_mode;

    /* Make sure that we do not include the file type bits when sending the
     * permission bits of the st_mode field.
     */
    perms &= ~S_IFMT;

    file_type = fxp_get_file_type(st->st_mode);

    len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), flags);
    len += sftp_msg_write_byte(&(fxb->buf), &(fxb->buflen), file_type);

    if (flags & SSH2_FX_ATTR_SIZE) {
      len += sftp_msg_write_long(&(fxb->buf), &(fxb->buflen), st->st_size);
    }

    if (flags & SSH2_FX_ATTR_OWNERGROUP) {
      const char *user_name, *group_name;

      if (user_owner == NULL) {
        user_name = pr_auth_uid2name(p, st->st_uid);

      } else {
        user_name = user_owner;
      }

      if (group_owner == NULL) {
        group_name = pr_auth_gid2name(p, st->st_gid);

      } else {
        group_name = group_owner;
      }

      len += sftp_msg_write_string(&(fxb->buf), &(fxb->buflen), user_name);
      len += sftp_msg_write_string(&(fxb->buf), &(fxb->buflen), group_name);
    }

    if (flags & SSH2_FX_ATTR_PERMISSIONS) {
      len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), perms);
    }

    if (flags & SSH2_FX_ATTR_ACCESSTIME) {
      len += sftp_msg_write_long(&(fxb->buf), &(fxb->buflen), st->st_atime);
    }

    if (flags & SSH2_FX_ATTR_MODIFYTIME) {
      len += sftp_msg_write_long(&(fxb->buf), &(fxb->buflen), st->st_mtime);
    }

    if (flags & SSH2_FX_ATTR_LINK_COUNT) {
      len += sftp_msg_write_int(&(fxb->buf), &(fxb->buflen), st->st_nlink);
    }

    if (flags & SSH2_FX_ATTR_EXTENDED) {
      len += fxp_xattrs_write(p, fxb, path);
    }
  }

  return len;
}

/* The strmode(3) function appears in some BSDs, but is not portable. */
static char *fxp_strmode(pool *p, mode_t mode) {
  char mode_str[12];

  memset(mode_str, '\0', sizeof(mode_str));
  sstrncpy(mode_str, "?--------- ", sizeof(mode_str));

  switch (mode & S_IFMT) {
    case S_IFREG:
      mode_str[0] = '-';
      break;

    case S_IFDIR:
      mode_str[0] = 'd';
      break;

    case S_IFLNK:
      mode_str[0] = 'l';
      break;

#ifdef S_IFSOCK
    case S_IFSOCK:
      mode_str[0] = 's';
      break;
#endif

    case S_IFIFO:
      mode_str[0] = 'p';
      break;

    case S_IFBLK:
      mode_str[0] = 'b';
      break;

    case S_IFCHR:
      mode_str[0] = 'c';
      break;
  }

  if (mode_str[0] != '?') {
    /* User perms */
    mode_str[1] = (mode & S_IRUSR) ? 'r' : '-';
    mode_str[2] = (mode & S_IWUSR) ? 'w' : '-';
    mode_str[3] = (mode & S_IXUSR) ?
      ((mode & S_ISUID) ? 's' : 'x') : ((mode & S_ISUID) ? 'S' : '-');

    /* Group perms */
    mode_str[4] = (mode & S_IRGRP) ? 'r' : '-';
    mode_str[5] = (mode & S_IWGRP) ? 'w' : '-';
    mode_str[6] = (mode & S_IXGRP) ?
      ((mode & S_ISGID) ? 's' : 'x') : ((mode & S_ISGID) ? 'S' : '-');

    /* World perms */
    mode_str[7] = (mode & S_IROTH) ? 'r' : '-';
    mode_str[8] = (mode & S_IWOTH) ? 'w' : '-';
    mode_str[9] = (mode & S_IXOTH) ?
      ((mode & S_ISVTX) ? 't' : 'x') : ((mode & S_ISVTX) ? 'T' : '-');
  }

  return pstrdup(p, mode_str);
}

static char *fxp_get_path_listing(pool *p, const char *path, struct stat *st,
    const char *user_owner, const char *group_owner) {
  const char *user, *group;
  char listing[1024], *mode_str, time_str[64];
  struct tm *t;
  int user_len, group_len;
  size_t time_strlen;
  time_t now = time(NULL);

  memset(listing, '\0', sizeof(listing));
  memset(time_str, '\0', sizeof(time_str));
 
  mode_str = fxp_strmode(p, st->st_mode); 

  if (fxp_use_gmt) {
    t = pr_gmtime(p, (const time_t *) &st->st_mtime);

  } else {
    t = pr_localtime(p, (const time_t *) &st->st_mtime);
  }

  /* Use strftime(3) to format the time entry for us.  Seems some SFTP clients
   * are *very* particular about this formatting.  Understandable, since
   * the SFTP Drafts for protocol version 3 did not actually define a format;
   * now most clients conform to the format used by OpenSSH.
   */

  if ((now - st->st_mtime) > (180 * 24 * 60 * 60)) {
    time_strlen = strftime(time_str, sizeof(time_str), "%b %e  %Y", t);

  } else {
    time_strlen = strftime(time_str, sizeof(time_str), "%b %e %H:%M", t);
  }

  if (time_strlen == 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION, "%s",
      "warning: strftime(3) returned 0");
  }

  if (user_owner == NULL) {
    user = pr_auth_uid2name(p, st->st_uid);

  } else {
    user = user_owner;
  }

  user_len = MAX(strlen(user), 8);

  if (group_owner == NULL) {
    group = pr_auth_gid2name(p, st->st_gid);

  } else {
    group = group_owner;
  }

  group_len = MAX(strlen(group), 8);

  pr_snprintf(listing, sizeof(listing)-1,
    "%s %3u %-*s %-*s %8" PR_LU " %s %s", mode_str,
    (unsigned int) st->st_nlink, user_len, user, group_len, group,
    (pr_off_t) st->st_size, time_str, path);
  return pstrdup(p, listing);
}

static struct fxp_dirent *fxp_get_dirent(pool *p, cmd_rec *cmd,
    const char *real_path, mode_t *fake_mode) {
  struct fxp_dirent *fxd;
  struct stat st;
  int hidden = 0, res;

  pr_fs_clear_cache2(real_path);
  if (pr_fsio_lstat(real_path, &st) < 0) {
    return NULL;
  }

  res = dir_check(p, cmd, G_DIRS, real_path, &hidden);
  if (res == 0 ||
      hidden == TRUE) {
    errno = EACCES;
    return NULL;
  }

  if (fake_mode != NULL) {
    mode_t mode;

    mode = *fake_mode;
    mode |= (st.st_mode & S_IFMT);

    if (S_ISDIR(st.st_mode)) {
      if (st.st_mode & S_IROTH) {
        mode |= S_IXOTH;
      }

      if (st.st_mode & S_IRGRP) {
        mode |= S_IXGRP;
      }

      if (st.st_mode & S_IRUSR) {
        mode |= S_IXUSR;
      }
    }

    st.st_mode = mode;
  }

  fxd = pcalloc(p, sizeof(struct fxp_dirent));  
  fxd->real_path = real_path;
  fxd->st = pcalloc(p, sizeof(struct stat));
  memcpy(fxd->st, &st, sizeof(struct stat));

  return fxd;
}

static uint32_t fxp_name_write(pool *p, struct fxp_buffer *fxb,
    const char *path, struct stat *st, uint32_t attr_flags,
    const char *user_owner, const char *group_owner) {
  uint32_t len = 0;
  const char *encoded_path;

  encoded_path = path;
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    encoded_path = sftp_utf8_encode_str(p, encoded_path);
  }

  len += sftp_msg_write_string(&(fxb->buf), &(fxb->buflen), encoded_path);

  if (fxp_session->client_version <= 3) {
    char *path_desc;

    path_desc = fxp_get_path_listing(p, path, st, user_owner, group_owner);
    if (fxp_session->client_version >= fxp_utf8_protocol_version) {
      path_desc = sftp_utf8_encode_str(p, path_desc);
    }

    len += sftp_msg_write_string(&(fxb->buf), &(fxb->buflen), path_desc);
  }

  len += fxp_attrs_write(p, fxb, path, st, attr_flags, user_owner, group_owner);
  return len;
}

/* FX Handle Mgmt */

static int fxp_handle_add(uint32_t channel_id, struct fxp_handle *fxh) {
  int res;

  if (fxp_session->handle_tab == NULL) {
    fxp_session->handle_tab = pr_table_alloc(fxp_session->pool, 0);
  }

  res = pr_table_add(fxp_session->handle_tab, fxh->name, fxh, sizeof(void *)); 
  if (res < 0) {
    if (errno != EEXIST) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error stashing handle: %s", strerror(errno));
    }
  }

  return res;
}

static struct fxp_handle *fxp_handle_create(pool *p) {
  unsigned char *data;
  char *handle;
  size_t data_len;
  pool *sub_pool;
  struct fxp_handle *fxh;

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "SFTP file handle pool");
  fxh = pcalloc(sub_pool, sizeof(struct fxp_handle));
  fxh->pool = sub_pool;

  /* Use 8 random bytes for our handle, which means 16 bytes as hex-encoded
   * characters.
   */
  data_len = 8;
  data = palloc(p, data_len);

  while (TRUE) {
    /* Keep trying until mktemp(3) returns a string that we haven't used
     * yet.  We need to avoid collisions.
     */
    pr_signals_handle();

    RAND_bytes(data, data_len);

    /* Encode the data as hex to create the handle ID. */
    handle = pr_str_bin2hex(fxh->pool, data, data_len, PR_STR_FL_HEX_USE_LC);

    if (fxp_handle_get(handle) == NULL) {
      fxh->name = handle;
      fxh->fh_st = pcalloc(fxh->pool, sizeof(struct stat));
      break;
    }

    pr_trace_msg(trace_channel, 4,
      "handle '%s' already used, generating another", handle);
  }

  return fxh;
}

/* NOTE: this function is ONLY called when the session is closed, for
 * "aborting" any file handles still left open by the client.
 */
static int fxp_handle_abort(const void *key_data, size_t key_datasz,
    const void *value_data, size_t value_datasz, void *user_data) {
  struct fxp_handle *fxh;
  char *abs_path, *curr_path = NULL, *real_path = NULL;
  char direction;
  unsigned char *delete_aborted_stores = NULL;
  cmd_rec *cmd = NULL;

  fxh = (struct fxp_handle *) value_data;
  delete_aborted_stores = user_data;

  /* Is this a file or a directory handle? */
  if (fxh->dirh != NULL) {
    cmd = fxp_cmd_alloc(fxh->pool, C_MLSD, (char *) fxh->dir);
    cmd->cmd_class = CL_DIRS;
    cmd->cmd_id = pr_cmd_get_id(C_MLSD);

    if (pr_fsio_closedir(fxh->dirh) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error closing aborted directory '%s': %s", fxh->dir, strerror(errno));
    }

    pr_response_clear(&resp_list);
    pr_response_clear(&resp_err_list);
    fxp_cmd_dispatch_err(cmd);

    fxh->dirh = NULL;
    return 0;
  }

  /* This filehandle may already have been closed.  If so, just move on to
   * the next one.
   */
  if (fxh->fh == NULL) {
    return 0;
  }

  curr_path = pstrdup(fxh->pool, fxh->fh->fh_path);
  real_path = curr_path;
  if (fxh->fh_real_path) {
    real_path = fxh->fh_real_path;
  }

  /* Write an 'incomplete' TransferLog entry for this. */
  abs_path = sftp_misc_vroot_abs_path(fxh->pool, real_path, TRUE);

  if (fxh->fh_flags == O_RDONLY) {
    direction = 'o';

  } else {
    direction = 'i';
  }

  if (fxh->fh_flags & O_APPEND) {
    cmd = fxp_cmd_alloc(fxh->pool, C_APPE, pstrdup(fxh->pool, curr_path));
    cmd->cmd_class = CL_WRITE;
    session.curr_cmd = C_APPE;

    if (pr_table_add(cmd->notes, "mod_xfer.store-path",
        pstrdup(fxh->pool, curr_path), 0) < 0) {
      if (errno != EEXIST) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error adding 'mod_xfer.store-path' note: %s", strerror(errno));
      }
    }

  } else if ((fxh->fh_flags & O_WRONLY) ||
             (fxh->fh_flags & O_RDWR)) {
    cmd = fxp_cmd_alloc(fxh->pool, C_STOR, pstrdup(fxh->pool, curr_path));
    cmd->cmd_class = CL_WRITE;
    session.curr_cmd = C_STOR;

    if (pr_table_add(cmd->notes, "mod_xfer.store-path",
        pstrdup(fxh->pool, curr_path), 0) < 0) {
      if (errno != EEXIST) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error adding 'mod_xfer.store-path' note: %s", strerror(errno));
      }
    }

  } else if (fxh->fh_flags == O_RDONLY) {
    cmd = fxp_cmd_alloc(fxh->pool, C_RETR, pstrdup(fxh->pool, curr_path));
    cmd->cmd_class = CL_READ;
    session.curr_cmd = C_RETR;

    if (pr_table_add(cmd->notes, "mod_xfer.retr-path",
        pstrdup(fxh->pool, curr_path), 0) < 0) {
      if (errno != EEXIST) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error adding 'mod_xfer.retr-path' note: %s", strerror(errno));
      }
    }
  }

  if (cmd != NULL) {
    /* Add a note indicating that this is a failed transfer. */
    fxp_cmd_note_file_status(cmd, "failed");
  }

  xferlog_write(0, pr_netaddr_get_sess_remote_name(), fxh->fh_bytes_xferred,
    abs_path, 'b', direction, 'r', session.user, 'i', "_");

  if (cmd) {
    pr_response_clear(&resp_list);
    pr_response_clear(&resp_err_list);

    pr_response_add_err(R_451, "%s: %s", cmd->arg, strerror(ECONNRESET));
    fxp_cmd_dispatch_err(cmd);
  }

  if (pr_fsio_close(fxh->fh) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error writing aborted file '%s': %s", fxh->fh->fh_path, strerror(errno));
  }

  fxh->fh = NULL;

  if (fxh->fh_flags != O_RDONLY) {
    if (fxh->fh_real_path) {
      /* This is a HiddenStores file. */
      if (delete_aborted_stores == NULL ||
          *delete_aborted_stores == TRUE) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "removing aborted uploaded file '%s'", curr_path);

        if (pr_fsio_unlink(curr_path) < 0) {
          if (errno != ENOENT) {
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
              "error unlinking file '%s': %s", curr_path,
              strerror(errno));
          }
        }
      }
    }
  }

  return 0;
}

static int fxp_handle_delete(struct fxp_handle *fxh) {
  if (fxp_session->handle_tab == NULL) {
    errno = EPERM;
    return -1;
  }

  (void) pr_table_remove(fxp_session->handle_tab, fxh->name, NULL);
  return 0;
}

static struct fxp_handle *fxp_handle_get(const char *handle) {
  struct fxp_handle *fxh;

  if (fxp_session->handle_tab == NULL) {
    errno = EPERM;
    return NULL;
  }

  fxh = (struct fxp_handle *) pr_table_get(fxp_session->handle_tab, handle,
    NULL);
  return fxh;
}

/* FX Message I/O */

static struct fxp_packet *fxp_packet_create(pool *p, uint32_t channel_id) {
  pool *sub_pool;
  struct fxp_packet *fxp;

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "SFTP packet pool");
  fxp = pcalloc(sub_pool, sizeof(struct fxp_packet));
  fxp->pool = sub_pool;
  fxp->channel_id = channel_id;

  return fxp;
}

static pool *curr_buf_pool = NULL;
static unsigned char *curr_buf = NULL;
static uint32_t curr_buflen = 0, curr_bufsz = 0;
static struct fxp_packet *curr_pkt = NULL;

static struct fxp_packet *fxp_packet_get_packet(uint32_t channel_id) {
  struct fxp_packet *fxp;

  if (curr_pkt) {
    return curr_pkt;
  }

  fxp = fxp_packet_create(fxp_pool, channel_id);
  return fxp;
}

static void fxp_packet_set_packet(struct fxp_packet *pkt) {
  curr_pkt = pkt;
}

static void fxp_packet_clear_cache(void) {
  curr_buflen = 0;
}

static uint32_t fxp_packet_get_cache(unsigned char **data) {
  *data = curr_buf;
  return curr_buflen;
}

static void fxp_packet_add_cache(unsigned char *data, uint32_t datalen) {
  if (curr_buf_pool == NULL) {
    curr_buf_pool = make_sub_pool(fxp_pool);
    pr_pool_tag(curr_buf_pool, "SFTP packet buffer pool");

    curr_buf = palloc(curr_buf_pool, FXP_PACKET_DATA_DEFAULT_SZ);
    curr_bufsz = fxp_packet_data_allocsz = FXP_PACKET_DATA_DEFAULT_SZ;
  }

  if (data == NULL ||
      datalen == 0) {
    return;
  }

  if (curr_buflen == 0) {
    if (curr_bufsz >= datalen) {
      /* We already have a buffer with enough space.  Nice. */

    } else {
      /* We need a larger buffer.  Round up to the nearest 1K size. */
      size_t sz;

      sz = sftp_crypto_get_size(datalen+1, 1024);

      if (fxp_packet_data_allocsz > FXP_PACKET_DATA_ALLOC_MAX_SZ) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "renewing SFTP packet data pool");
        destroy_pool(curr_buf_pool);

        curr_buf_pool = make_sub_pool(fxp_pool);
        pr_pool_tag(curr_buf_pool, "SFTP packet buffer pool");

        curr_bufsz = 0;
      }

      curr_bufsz = sz;
      curr_buf = palloc(curr_buf_pool, curr_bufsz);
      fxp_packet_data_allocsz += sz;
    }

    /* We explicitly want to use memmove(3) here rather than memcpy(3),
     * since it is possible (and likely) that after reading data out
     * of this buffer, there will be leftover data which is put back into
     * the buffer, only at a different offset.  This means that the
     * source and destination pointers CAN overlap; using memcpy(3) would
     * lead to subtle memory copy issue (e.g. Bug#3743).
     *
     * This manifested as hard-to-reproduce SFTP upload/download stalls,
     * segfaults, etc, due to corrupted memory being read out as
     * packet lengths and such.
     */
    memmove(curr_buf, data, datalen);
    curr_buflen = datalen;

    return;
  }

  if (curr_buflen > 0) {
    if (curr_bufsz >= (curr_buflen + datalen)) {
      /* We already have a buffer with enough space.  Nice. */

    } else {
      /* We need a larger buffer.  Round up to the nearest 1K size. */
      size_t sz;

      sz = sftp_crypto_get_size(curr_buflen + datalen + 1, 1024);

      if (fxp_packet_data_allocsz > FXP_PACKET_DATA_ALLOC_MAX_SZ) {
        pool *tmp_pool;
        char *tmp_data;
        uint32_t tmp_datalen;

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "renewing SFTP packet data pool");

        tmp_pool = make_sub_pool(fxp_pool);
        tmp_datalen = curr_buflen;
        tmp_data = palloc(tmp_pool, tmp_datalen);                
        memcpy(tmp_data, curr_buf, tmp_datalen);
        
        destroy_pool(curr_buf_pool);

        curr_buf_pool = make_sub_pool(fxp_pool);
        pr_pool_tag(curr_buf_pool, "SFTP packet buffer pool");

        curr_bufsz = sz;
        curr_buf = palloc(curr_buf_pool, curr_bufsz);
        fxp_packet_data_allocsz += sz;

        memcpy(curr_buf, tmp_data, tmp_datalen);
        curr_buflen = tmp_datalen;

        destroy_pool(tmp_pool);
      }
    }

    /* Append the SSH2 data to the current unconsumed buffer.
     *
     * We explicitly want to use memmove(3) here rather than memcpy(3),
     * since it is possible (and likely) that after reading data out
     * of this buffer, there will be leftover data which is put back into
     * the buffer, only at a different offset.  This means that the
     * source and destination pointers CAN overlap; using memcpy(3) would
     * lead to subtle memory copy issue (e.g. Bug#3743).
     *
     * This manifested as hard-to-reproduce SFTP upload/download stalls,
     * segfaults, etc, due to corrupted memory being read out as
     * packet lengths and such.
     */
    memmove(curr_buf + curr_buflen, data, datalen);
    curr_buflen += datalen;
  }

  return;
}

static struct fxp_packet *fxp_packet_read(uint32_t channel_id,
    unsigned char **data, uint32_t *datalen, int *have_cache) {
  struct fxp_packet *fxp;
  unsigned char *buf;
  uint32_t buflen;

  if (datalen) {
    pr_trace_msg(trace_channel, 9,
      "reading SFTP data from SSH2 packet buffer (%lu bytes)",
      (unsigned long) *datalen);
    fxp_packet_add_cache(*data, *datalen);
  }

  buflen = fxp_packet_get_cache(&buf);
  pr_trace_msg(trace_channel, 19,
    "using %lu bytes of SSH2 packet buffer data", (unsigned long) buflen);

  fxp = fxp_packet_get_packet(channel_id);

  if (!(fxp->state & FXP_PACKET_HAVE_PACKET_LEN)) {
    /* Make sure we have enough data in the buffer to cover the packet len. */
    if (buflen < sizeof(uint32_t)) {
      fxp_packet_set_packet(fxp);

      /* We didn't consume any data, so no need to call
       * clear_cache()/add_cache().
       */
      *have_cache = TRUE;

      return NULL;
    }

    fxp->packet_len = sftp_msg_read_int(fxp->pool, &buf, &buflen);
    fxp->state |= FXP_PACKET_HAVE_PACKET_LEN;

    pr_trace_msg(trace_channel, 19,
      "read SFTP request packet len %lu from SSH2 packet buffer "
      "(%lu bytes remaining in buffer)", (unsigned long) fxp->packet_len,
      (unsigned long) buflen);

    if (buflen == 0) {
      fxp_packet_set_packet(fxp);
      fxp_packet_clear_cache();
      *have_cache = FALSE;

      return NULL;
    }

  } else {
    pr_trace_msg(trace_channel, 19,
      "already have SFTP request packet len %lu from previous buffer data",
      (unsigned long) fxp->packet_len);
  }

  if (!(fxp->state & FXP_PACKET_HAVE_REQUEST_TYPE)) {
    /* Make sure we have enough data in the buffer to cover the request type. */
    if (buflen < sizeof(char)) {
      fxp_packet_set_packet(fxp);
      fxp_packet_clear_cache();
      fxp_packet_add_cache(buf, buflen);
      *have_cache = TRUE;

      return NULL;
    }

    fxp->request_type = sftp_msg_read_byte(fxp->pool, &buf, &buflen);
    fxp->state |= FXP_PACKET_HAVE_REQUEST_TYPE;

    pr_trace_msg(trace_channel, 19,
      "read SFTP request type %d from SSH2 packet buffer "
      "(%lu bytes remaining in buffer)", (int) fxp->request_type,
      (unsigned long) buflen);

    if (buflen == 0) {
      fxp_packet_set_packet(fxp);
      fxp_packet_clear_cache();
      *have_cache = FALSE;

      return NULL;
    }

  } else {
    pr_trace_msg(trace_channel, 19,
      "already have SFTP request type %d from previous buffer data",
      fxp->request_type);
  }

  if (!(fxp->state & FXP_PACKET_HAVE_PAYLOAD_SIZE)) {
    /* And take back one byte for whose request_type this is... */
    fxp->payload_sz = fxp->packet_len - 1;
    fxp->state |= FXP_PACKET_HAVE_PAYLOAD_SIZE;

    pr_trace_msg(trace_channel, 19,
      "read SFTP request payload size %lu from SSH2 packet buffer "
      "(%lu bytes remaining in buffer)", (unsigned long) fxp->payload_sz,
      (unsigned long) buflen);

  } else {
    pr_trace_msg(trace_channel, 19,
      "already have SFTP request payload size %lu from previous buffer data",
      (unsigned long) fxp->payload_sz);
  }

  if (!(fxp->state & FXP_PACKET_HAVE_REQUEST_ID)) {
    if (fxp->request_type != SFTP_SSH2_FXP_INIT) {
      /* Make sure we have enough data in the buffer to cover the request ID. */
      if (buflen < sizeof(uint32_t)) {
        fxp_packet_set_packet(fxp);
        fxp_packet_clear_cache();
        fxp_packet_add_cache(buf, buflen);
        *have_cache = TRUE;

        return NULL;
      }

      /* The INIT and VERSION requests do not use request IDs. */
      fxp->request_id = sftp_msg_read_int(fxp->pool, &buf, &buflen);
      fxp->payload_sz -= sizeof(uint32_t);

      pr_trace_msg(trace_channel, 19,
        "read SFTP request ID %lu from SSH2 packet buffer "
        "(%lu bytes remaining in buffer)", (unsigned long) fxp->request_id,
        (unsigned long) buflen);
    }

    fxp->state |= FXP_PACKET_HAVE_REQUEST_ID;

    if (buflen == 0) {
      fxp_packet_set_packet(fxp);
      fxp_packet_clear_cache();
      *have_cache = FALSE;

      return NULL;
    }

  } else {
    pr_trace_msg(trace_channel, 19,
      "already have SFTP request ID %lu from previous buffer data",
      (unsigned long) fxp->request_id);
  }

  if (!(fxp->state & FXP_PACKET_HAVE_PAYLOAD)) {
    uint32_t payload_remaining;

    /* The first question is: do we have any existing payload data?
     *
     * 1. Have no payload data:
     *   a. Packet buffer is exactly size of needed payload data.
     *     This means that we will get the full payload, and there will be
     *     no data left over in the packet buffer.
     *
     *   b. Packet buffer is larger than size of needed payload data.
     *     This means that we will get the full payload, and there will be
     *     data left over in the packet buffer.
     *
     *   c. Packet buffer is smaller than size of needed payload data.
     *     This means that we will get only a partial payload, and there will
     *     be no data left over in the packet buffer.
     *
     * 2. Have existing payload data:
     *   a. Packet buffer is exactly size of remaining payload data.
     *     This means that we will get the full payload, and there will be
     *     no data left over in the packet buffer.
     *
     *   b. Packet buffer is larger than size of remaining payload data.
     *     This means that we will get the full payload, and there will be
     *     data left over in the packet buffer.
     *
     *   c. Packet buffer is smaller than size of remaining payload data.
     *     This means that we will get only a partial payload, and there will
     *     be no data left over in the packet buffer.
     *
     * To simplify the code, we can say that if we have no payload data,
     * it can be handled the same as a partial payload of length zero.
     */

    if (fxp->payload == NULL) {
      /* Make sure we have a payload buffer allocated. */
      fxp->payload = pcalloc(fxp->pool, fxp->payload_sz);
      fxp->payload_len = 0;
    }

    /* Now determine the amount of bytes remaining before we have the full
     * payload.
     */
    payload_remaining = fxp->payload_sz - fxp->payload_len;

    /* First case: the packet buffer is exactly the size of the remaining
     * payload data.
     */
    if (buflen == payload_remaining) {
      pr_trace_msg(trace_channel, 19,
        "filling remaining SFTP request payload (%lu of %lu total bytes) "
        "from SSH2 packet buffer (%lu bytes in buffer)",
        (unsigned long) payload_remaining, (unsigned long) fxp->payload_sz,
        (unsigned long) buflen);

      memcpy(fxp->payload + fxp->payload_len, buf, buflen);
      fxp->payload_len = buflen;
      fxp->state |= FXP_PACKET_HAVE_PAYLOAD;

      fxp_packet_set_packet(NULL);
      fxp_packet_clear_cache();
      *have_cache = FALSE;

      pr_trace_msg(trace_channel, 19, "completely filled payload of %lu bytes "
        "(0 bytes remaining in buffer)", (unsigned long) fxp->payload_sz);
      return fxp;
    }

    /* Second case: the packet buffer is larger than the size of the remaining
     * payload data.
     */
    if (buflen > payload_remaining) {
      pr_trace_msg(trace_channel, 19,
        "filling remaining SFTP request payload (%lu of %lu total bytes) "
        "from SSH2 packet buffer (%lu bytes in buffer)",
        (unsigned long) payload_remaining, (unsigned long) fxp->payload_sz,
        (unsigned long) buflen);

      memcpy(fxp->payload + fxp->payload_len, buf, payload_remaining);
      fxp->payload_len += payload_remaining;
      fxp->state |= FXP_PACKET_HAVE_PAYLOAD;

      buflen -= payload_remaining;
      buf += payload_remaining;

      fxp_packet_set_packet(NULL);
      fxp_packet_clear_cache();
      fxp_packet_add_cache(buf, buflen);
      *have_cache = TRUE;

      pr_trace_msg(trace_channel, 19, "completely filled payload of %lu bytes "
        "(%lu bytes remaining in buffer)", (unsigned long) fxp->payload_sz,
        (unsigned long) buflen);
      return fxp;
    }

    /* Third (and remaining) case: the packet buffer is smaller than the size
     * of the remaining payload data.
     */
    pr_trace_msg(trace_channel, 19,
      "filling remaining SFTP request payload (%lu of %lu total bytes) "
      "from SSH2 packet buffer (%lu bytes in buffer)",
      (unsigned long) payload_remaining, (unsigned long) fxp->payload_sz,
      (unsigned long) buflen);

    memcpy(fxp->payload + fxp->payload_len, buf, buflen);
    fxp->payload_len += buflen;

    fxp_packet_set_packet(fxp);
    fxp_packet_clear_cache();
    *have_cache = FALSE;

  } else {
    pr_trace_msg(trace_channel, 19,
      "already have SFTP payload (%lu bytes) from previous buffer data",
      (unsigned long) fxp->payload_sz);
  }

  return NULL;
}

static int fxp_packet_write(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;
  int res;

  /* Use a buffer that's a little larger than the FX packet size */
  buflen = bufsz = fxp->payload_sz + 32;
  buf = ptr = palloc(fxp->pool, bufsz);

  sftp_msg_write_data(&buf, &buflen, fxp->payload, fxp->payload_sz, TRUE);

  res = sftp_channel_write_data(fxp->pool, fxp->channel_id, ptr,
    (bufsz - buflen));
  return res;
}

/* Miscellaneous */

static void fxp_version_add_vendor_id_ext(pool *p, unsigned char **buf,
    uint32_t *buflen) {
  unsigned char *buf2, *ptr2;
  const char *vendor_name, *product_name, *product_version;
  uint32_t bufsz2, buflen2;
  uint64_t build_number;
  struct fxp_extpair ext;

  bufsz2 = buflen2 = 512;
  ptr2 = buf2 = sftp_msg_getbuf(p, bufsz2);

  vendor_name = "ProFTPD Project";
  product_name = "mod_sftp";
  product_version = MOD_SFTP_VERSION;
  build_number = pr_version_get_number();

  sftp_msg_write_string(&buf2, &buflen2, vendor_name);
  sftp_msg_write_string(&buf2, &buflen2, product_name);
  sftp_msg_write_string(&buf2, &buflen2, product_version);
  sftp_msg_write_long(&buf2, &buflen2, build_number);

  ext.ext_name = "vendor-id";
  ext.ext_data = ptr2;
  ext.ext_datalen = (bufsz2 - buflen2);

  pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s = "
     "{ vendorName = '%s', productName = '%s', productVersion = '%s', "
     "buildNumber = %" PR_LU " }", ext.ext_name, vendor_name, product_name,
     product_version, (pr_off_t) build_number);

  fxp_msg_write_extpair(buf, buflen, &ext);
}

static void fxp_version_add_version_ext(pool *p, unsigned char **buf,
    uint32_t *buflen) {
  register unsigned int i;
  struct fxp_extpair ext;
  char *versions_str = "";

  if (!(fxp_ext_flags & SFTP_FXP_EXT_VERSION_SELECT)) {
    return;
  }

  ext.ext_name = "versions";

  /* The versions we report to the client depend on the min/max client
   * versions, which may have been configured differently via SFTPClientMatch.
   */

  for (i = fxp_min_client_version; i <= fxp_max_client_version; i++) {
    switch (i) {
      case 1:
        /* Skip version 1; it is not in the list of version strings defined
         * in Section 4.6 of the SFTP Draft.
         */
        break;

      case 2:
        versions_str = pstrcat(p, versions_str, *versions_str ? "," : "",
          "2", NULL);
        break;

      case 3:
        versions_str = pstrcat(p, versions_str, *versions_str ? "," : "",
          "3", NULL);
        break;

#ifdef PR_USE_NLS
      /* We can only advertise support for these protocol versions if
       * --enable-nls has been used, as they require UTF8 support.
       */
      case 4:
        versions_str = pstrcat(p, versions_str, *versions_str ? "," : "",
          "4", NULL);
        break;

      case 5:
        versions_str = pstrcat(p, versions_str, *versions_str ? "," : "",
          "5", NULL);
        break;

      case 6:
        versions_str = pstrcat(p, versions_str, *versions_str ? "," : "",
          "6", NULL);
        break;
#endif
    }
  }

  ext.ext_data = (unsigned char *) versions_str;
  ext.ext_datalen = strlen(versions_str);

  pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s = '%s'", ext.ext_name,
    ext.ext_data);
  fxp_msg_write_extpair(buf, buflen, &ext);

  /* The sending of this extension is necessary in order to support any
   * 'version-select' requests from the client, as per Section 4.6 of the
   * SFTP Draft.  That is, if we don't send the 'versions' extension and the
   * client tries to send us a 'version-select', then we MUST close the
   * connection.
   */
  allow_version_select = TRUE;
}

static void fxp_version_add_openssh_exts(pool *p, unsigned char **buf,
    uint32_t *buflen) {
  (void) p;

  /* These are OpenSSH-specific SFTP extensions. */

  if (fxp_ext_flags & SFTP_FXP_EXT_FSYNC) {
    struct fxp_extpair ext;

    ext.ext_name = "fsync@openssh.com";
    ext.ext_data = (unsigned char *) "1";
    ext.ext_datalen = 1;

    pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s = '%s'", ext.ext_name,
      ext.ext_data);
    fxp_msg_write_extpair(buf, buflen, &ext);
  }

  if (fxp_ext_flags & SFTP_FXP_EXT_POSIX_RENAME) {
    struct fxp_extpair ext;

    ext.ext_name = "posix-rename@openssh.com";
    ext.ext_data = (unsigned char *) "1";
    ext.ext_datalen = 1;

    pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s = '%s'", ext.ext_name,
      ext.ext_data);
    fxp_msg_write_extpair(buf, buflen, &ext);
  }

#ifdef HAVE_SYS_STATVFS_H
  if (fxp_ext_flags & SFTP_FXP_EXT_STATVFS) {
    struct fxp_extpair ext;

    ext.ext_name = "statvfs@openssh.com";
    ext.ext_data = (unsigned char *) "2";
    ext.ext_datalen = 1;

    pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s = '%s'", ext.ext_name,
      ext.ext_data);
    fxp_msg_write_extpair(buf, buflen, &ext);

    ext.ext_name = "fstatvfs@openssh.com";
    ext.ext_data = (unsigned char *) "2";
    ext.ext_datalen = 1;

    pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s = '%s'",
      ext.ext_name, ext.ext_data);
    fxp_msg_write_extpair(buf, buflen, &ext);
  }
#endif

  if (fxp_ext_flags & SFTP_FXP_EXT_HARDLINK) {
    struct fxp_extpair ext;

    ext.ext_name = "hardlink@openssh.com";
    ext.ext_data = (unsigned char *) "1";
    ext.ext_datalen = 1;

    pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s = '%s'", ext.ext_name,
      ext.ext_data);
    fxp_msg_write_extpair(buf, buflen, &ext);
  }

  if (fxp_ext_flags & SFTP_FXP_EXT_XATTR) {
    struct fxp_extpair ext;

    ext.ext_name = "xattr@proftpd.org";
    ext.ext_data = (unsigned char *) "1";
    ext.ext_datalen = 1;

    pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s = '%s'", ext.ext_name,
      ext.ext_data);
    fxp_msg_write_extpair(buf, buflen, &ext);
  }
}

static void fxp_version_add_newline_ext(pool *p, unsigned char **buf,
    uint32_t *buflen) {
  struct fxp_extpair ext;

  (void) p;

  ext.ext_name = "newline";
  ext.ext_data = (unsigned char *) "\n";
  ext.ext_datalen = 1;

  pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s = '\n'", ext.ext_name);
  fxp_msg_write_extpair(buf, buflen, &ext);
}

static void fxp_version_add_supported_ext(pool *p, unsigned char **buf,
    uint32_t *buflen) {
  struct fxp_extpair ext;
  uint32_t attrs_len, attrs_sz;
  unsigned char *attrs_buf, *attrs_ptr;
  uint32_t file_mask, bits_mask, open_mask, access_mask, max_read_size;
  unsigned int ext_count;

  ext.ext_name = "supported";

  attrs_sz = attrs_len = 1024;
  attrs_ptr = attrs_buf = sftp_msg_getbuf(p, attrs_sz);

  file_mask = SSH2_FX_ATTR_SIZE|SSH2_FX_ATTR_PERMISSIONS|
    SSH2_FX_ATTR_ACCESSTIME|SSH2_FX_ATTR_MODIFYTIME|SSH2_FX_ATTR_OWNERGROUP;

  bits_mask = 0;

  open_mask = SSH2_FXF_WANT_READ_DATA|SSH2_FXF_WANT_WRITE_DATA|
    SSH2_FXF_WANT_APPEND_DATA|SSH2_FXF_WANT_READ_ATTRIBUTES|
    SSH2_FXF_WANT_WRITE_ATTRIBUTES;

  access_mask = SSH2_FXF_CREATE_NEW|SSH2_FXF_CREATE_TRUNCATE|
    SSH2_FXF_OPEN_EXISTING|SSH2_FXF_OPEN_OR_CREATE|
    SSH2_FXF_TRUNCATE_EXISTING|SSH2_FXF_ACCESS_APPEND_DATA|
    SSH2_FXF_ACCESS_APPEND_DATA_ATOMIC;

  max_read_size = 0;

  sftp_msg_write_int(&attrs_buf, &attrs_len, file_mask);
  sftp_msg_write_int(&attrs_buf, &attrs_len, bits_mask);
  sftp_msg_write_int(&attrs_buf, &attrs_len, open_mask);
  sftp_msg_write_int(&attrs_buf, &attrs_len, access_mask);
  sftp_msg_write_int(&attrs_buf, &attrs_len, max_read_size);

  /* The possible extensions to advertise here are:
   *
   *  check-file
   *  copy-file
   *  space-available
   *  vendor-id
   */

  ext_count = 4;

  if (!(fxp_ext_flags & SFTP_FXP_EXT_CHECK_FILE)) {
    ext_count--;
  }

  if (!(fxp_ext_flags & SFTP_FXP_EXT_COPY_FILE)) {
    ext_count--;
  }

  if (!(fxp_ext_flags & SFTP_FXP_EXT_SPACE_AVAIL)) {
    ext_count--;
  }

  /* We don't decrement the extension count if the 'vendor-id' extension
   * is disabled.  By advertisting the 'vendor-id' extension here, we are
   * telling the client that it can send us its vendor information.
   */

  if (ext_count > 0) {
    unsigned char *exts_buf, *exts_ptr;
    uint32_t exts_len, exts_sz;

    exts_len = exts_sz = 256;
    exts_buf = exts_ptr = palloc(p, exts_sz);

    if (fxp_ext_flags & SFTP_FXP_EXT_CHECK_FILE) {
      pr_trace_msg(trace_channel, 11, "%s", "+ SFTP extension: check-file");
      sftp_msg_write_string(&exts_buf, &exts_len, "check-file");
    }

    if (fxp_ext_flags & SFTP_FXP_EXT_COPY_FILE) {
      pr_trace_msg(trace_channel, 11, "%s", "+ SFTP extension: copy-file");
      sftp_msg_write_string(&exts_buf, &exts_len, "copy-file");
    }

    if (fxp_ext_flags & SFTP_FXP_EXT_SPACE_AVAIL) {
      pr_trace_msg(trace_channel, 11, "%s",
        "+ SFTP extension: space-available");
      sftp_msg_write_string(&exts_buf, &exts_len, "space-available");
    }

    /* We always send the 'vendor-id' extension; it lets the client know
     * that it can send its vendor information to us.
     */
    pr_trace_msg(trace_channel, 11, "%s", "+ SFTP extension: vendor-id");
    sftp_msg_write_string(&exts_buf, &exts_len, "vendor-id");

    sftp_msg_write_data(&attrs_buf, &attrs_len, exts_ptr,
      (exts_sz - exts_len), FALSE);
  }

  ext.ext_data = attrs_ptr;
  ext.ext_datalen = (attrs_sz - attrs_len);

  pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s", ext.ext_name);
  fxp_msg_write_extpair(buf, buflen, &ext);
}

static void fxp_version_add_supported2_ext(pool *p, unsigned char **buf,
    uint32_t *buflen) {
  struct fxp_extpair ext;
  uint32_t attrs_len, attrs_sz;
  unsigned char *attrs_buf, *attrs_ptr;
  uint32_t file_mask, bits_mask, open_mask, access_mask, max_read_size;
  uint16_t open_lock_mask, lock_mask;
  unsigned int ext_count;

  ext.ext_name = "supported2";

  attrs_sz = attrs_len = 1024;
  attrs_ptr = attrs_buf = sftp_msg_getbuf(p, attrs_sz);

  file_mask = SSH2_FX_ATTR_SIZE|SSH2_FX_ATTR_PERMISSIONS|
    SSH2_FX_ATTR_ACCESSTIME|SSH2_FX_ATTR_MODIFYTIME|SSH2_FX_ATTR_OWNERGROUP;
#ifdef PR_USE_XATTR
  file_mask |= SSH2_FX_ATTR_EXTENDED;
#endif /* PR_USE_XATTR */

  bits_mask = 0;

  open_mask = SSH2_FXF_WANT_READ_DATA|SSH2_FXF_WANT_WRITE_DATA|
    SSH2_FXF_WANT_APPEND_DATA|SSH2_FXF_WANT_READ_ATTRIBUTES|
    SSH2_FXF_WANT_WRITE_ATTRIBUTES;

  access_mask = SSH2_FXF_CREATE_NEW|SSH2_FXF_CREATE_TRUNCATE|
    SSH2_FXF_OPEN_EXISTING|SSH2_FXF_OPEN_OR_CREATE|
    SSH2_FXF_TRUNCATE_EXISTING|SSH2_FXF_ACCESS_APPEND_DATA|
    SSH2_FXF_ACCESS_APPEND_DATA_ATOMIC;

  max_read_size = 0;

  /* Set only one bit, to indicate that locking is not supported for
   * OPEN commands.
   */
  open_lock_mask = 0x0001;

  /* Indicate that we support the classic locks: READ+WRITE+ADVISORY and
   * WRITE+ADVISORY.  Note that we do not need to include DELETE, since this
   * mask is only for LOCK commands, not UNLOCK commands.
   */
  lock_mask = 0x0c01;

  sftp_msg_write_int(&attrs_buf, &attrs_len, file_mask);
  sftp_msg_write_int(&attrs_buf, &attrs_len, bits_mask);
  sftp_msg_write_int(&attrs_buf, &attrs_len, open_mask);
  sftp_msg_write_int(&attrs_buf, &attrs_len, access_mask);
  sftp_msg_write_int(&attrs_buf, &attrs_len, max_read_size);
  fxp_msg_write_short(&attrs_buf, &attrs_len, open_lock_mask);
  fxp_msg_write_short(&attrs_buf, &attrs_len, lock_mask);

  /* Attribute extensions */
  sftp_msg_write_int(&attrs_buf, &attrs_len, 0);

  /* The possible extensions to advertise here are:
   *
   *  check-file
   *  copy-file
   *  space-available
   *  vendor-id
   *
   * Note that we don't have to advertise the @openssh.com extensions, since
   * they occur for protocol versions which don't support 'supported2'.  And
   * we don't have to list 'version-select', since the sending of the
   * 'versions' extension in our VERSION automatically enables use of this
   * extension by the client.
   */
  ext_count = 4;

  if (!(fxp_ext_flags & SFTP_FXP_EXT_CHECK_FILE)) {
    ext_count--;
  }

  if (!(fxp_ext_flags & SFTP_FXP_EXT_COPY_FILE)) {
    ext_count--;
  }

  if (!(fxp_ext_flags & SFTP_FXP_EXT_SPACE_AVAIL)) {
    ext_count--;
  }

  /* We don't decrement the extension count if the 'vendor-id' extension
   * is disabled.  By advertisting the 'vendor-id' extension here, we are
   * telling the client that it can send us its vendor information.
   */

  /* Additional protocol extensions (why these appear in 'supported2' is
   * confusing to me, too).
   */
  sftp_msg_write_int(&attrs_buf, &attrs_len, ext_count);

  if (ext_count > 0) {
    if (fxp_ext_flags & SFTP_FXP_EXT_CHECK_FILE) {
      pr_trace_msg(trace_channel, 11, "%s", "+ SFTP extension: check-file");
      sftp_msg_write_string(&attrs_buf, &attrs_len, "check-file");
    }

    if (fxp_ext_flags & SFTP_FXP_EXT_COPY_FILE) {
      pr_trace_msg(trace_channel, 11, "%s", "+ SFTP extension: copy-file");
      sftp_msg_write_string(&attrs_buf, &attrs_len, "copy-file");
    }

    if (fxp_ext_flags & SFTP_FXP_EXT_SPACE_AVAIL) {
      pr_trace_msg(trace_channel, 11, "%s",
        "+ SFTP extension: space-available");
      sftp_msg_write_string(&attrs_buf, &attrs_len, "space-available");
    }

    /* We always send the 'vendor-id' extension; it lets the client know
     * that it can send its vendor information to us.
     */
    pr_trace_msg(trace_channel, 11, "%s", "+ SFTP extension: vendor-id");
    sftp_msg_write_string(&attrs_buf, &attrs_len, "vendor-id");
  }
 
  ext.ext_data = attrs_ptr;
  ext.ext_datalen = (attrs_sz - attrs_len);

  pr_trace_msg(trace_channel, 11, "+ SFTP extension: %s", ext.ext_name);
  fxp_msg_write_extpair(buf, buflen, &ext);
}

/* SFTP Extension handlers */

static int fxp_handle_ext_check_file(struct fxp_packet *fxp, char *digest_list,
    char *path, off_t offset, off_t len, uint32_t blocksz) {
  unsigned char *buf, *ptr;
  char *supported_digests;
  const char *digest_name, *reason;
  uint32_t buflen, bufsz, expected_buflen, status_code;
  struct fxp_packet *resp;
  int data_len, res, xerrno = 0;
  struct stat st;
  pr_fh_t *fh;
  cmd_rec *cmd;
  unsigned long nblocks;
  off_t range_len, total_len = 0;
  void *data;
  BIO *bio;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  EVP_MD_CTX md_ctx;
#endif /* prior to OpenSSL-1.1.0 */
  EVP_MD_CTX *pctx;
  const EVP_MD *md;

  pr_trace_msg(trace_channel, 8, "client sent check-file request: "
    "path = '%s', digests = '%s', offset = %" PR_LU ", len = %" PR_LU
    ", block size = %lu", path, digest_list, (pr_off_t) offset, (pr_off_t) len,
    (unsigned long) blocksz);

  /* We could end up with lots of digests to write, if the file is large
   * and/or the block size is small.  Be prepared.
   */
  buflen = bufsz = (FXP_RESPONSE_DATA_DEFAULT_SZ * 2);
  buf = ptr = palloc(fxp->pool, bufsz);

  /* The minimum block size required by this extension is 256 bytes. */
  if (blocksz != 0 &&
      blocksz < 256) {
    xerrno = EINVAL;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SFTP client check-file request sent invalid block size "
      "(%lu bytes <= 256)", (unsigned long) blocksz);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_fs_clear_cache2(path);
  if (pr_fsio_lstat(path, &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      char link_path[PR_TUNABLE_PATH_MAX];
      int link_len;

      memset(link_path, '\0', sizeof(link_path));
      link_len = dir_readlink(fxp->pool, path, link_path, sizeof(link_path)-1,
        PR_DIR_READLINK_FL_HANDLE_REL_PATH);
      if (link_len > 0) {
        link_path[link_len] = '\0';
        path = pstrdup(fxp->pool, link_path);
      }
    }
  }

  pr_fs_clear_cache2(path);
  res = pr_fsio_lstat(path, &st);
  if (res < 0) {
    xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to lstat path '%s': %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (S_ISDIR(st.st_mode)) {
    xerrno = EISDIR;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SFTP client check-file requested on a directory, denying");

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (!S_ISREG(st.st_mode) &&
      !S_ISLNK(st.st_mode)) {
    xerrno = EINVAL;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SFTP client check-file request not for file or symlink, denying");

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (offset >= st.st_size) {
    xerrno = EINVAL;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client check-file request sent invalid offset (%" PR_LU
      " >= %" PR_LU " file size)", (pr_off_t) offset, (pr_off_t) st.st_size);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  cmd = fxp_cmd_alloc(fxp->pool, "SITE_DIGEST", pstrdup(fxp->pool, path));
  if (!dir_check(fxp->pool, cmd, "READ", path, NULL)) {
    xerrno = EACCES;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "'check-file' of '%s' blocked by <Limit> configuration", path);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  supported_digests = "md5,sha1";
#ifdef HAVE_SHA256_OPENSSL
  supported_digests = pstrcat(fxp->pool, supported_digests, ",sha224,sha256",
    NULL);
#endif
#ifdef HAVE_SHA512_OPENSSL
  supported_digests = pstrcat(fxp->pool, supported_digests, ",sha384,sha512",
    NULL);
#endif

  digest_name = sftp_misc_namelist_shared(fxp->pool, digest_list,
    supported_digests);
  if (digest_name == NULL) {
    xerrno = EINVAL;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "no supported digests in client check-file request "
      "(client sent '%s', server supports '%s')", digest_list,
      supported_digests);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (len == 0) {
    range_len = st.st_size - offset;

  } else {
    range_len = offset + len;
  }

  if (blocksz == 0) {
    nblocks = 1;

  } else {
    nblocks = (unsigned long) (range_len / blocksz);
    if (range_len % blocksz != 0) {
      nblocks++;
    }
  }

  pr_trace_msg(trace_channel, 15, "for check-file request on '%s', "
    "calculate %s digest of %lu %s", path, digest_name, nblocks,
    nblocks == 1 ? "block/checksum" : "nblocks/checksums");

  fh = pr_fsio_open(path, O_RDONLY|O_NONBLOCK);
  if (fh == NULL) {
    xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to open path '%s': %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (pr_fsio_set_block(fh) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error setting fd %d (file '%s') as blocking: %s", fh->fh_fd,
      fh->fh_path, strerror(errno));
  }

  if (pr_fsio_lseek(fh, offset, SEEK_SET) < 0) {
    xerrno = errno;

    pr_fsio_close(fh);

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to seek to offset %" PR_LU " in '%s': %s", (pr_off_t) offset,
      path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  md = EVP_get_digestbyname(digest_name);
  if (md == NULL) {
    xerrno = EINVAL;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to support %s digests: %s", digest_name,
      sftp_crypto_get_errors());

    pr_fsio_close(fh);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    /* Since we already started writing the EXTENDED_REPLY, we have
     * to reset the pointers and overwrite the existing message.
     */
    buf = ptr;
    buflen = bufsz;

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* Calculate the size of the response buffer, based on the number of blocks.
   * Our already-allocated response buffer might be too small (see Issue #576).
   *
   * Each block needs at most EVP_MAX_MD_SIZE bytes, plus 4 bytes for the
   * length prefix.
   */
  expected_buflen = FXP_RESPONSE_DATA_DEFAULT_SZ +
    (nblocks * (EVP_MAX_MD_SIZE + 4));
  if (buflen < expected_buflen) {
    pr_trace_msg(trace_channel, 15, "allocated larger buffer (%lu bytes) for "
      "check-file request on '%s', %s digest, %lu %s",
      (unsigned long) expected_buflen, path, digest_name, nblocks,
      nblocks == 1 ? "block/checksum" : "nblocks/checksums");

    buflen = bufsz = expected_buflen;
    buf = ptr = palloc(fxp->pool, bufsz);
  }

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  pctx = &md_ctx;
  EVP_MD_CTX_init(pctx);
#else
  pctx = EVP_MD_CTX_new();
#endif /* prior to OpenSSL-1.1.0 */

  bio = BIO_new(BIO_s_fd());
  BIO_set_fd(bio, PR_FH_FD(fh), BIO_NOCLOSE);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_EXTENDED_REPLY);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);
  sftp_msg_write_string(&buf, &buflen, digest_name);

  pr_trace_msg(trace_channel, 8,
    "sending response: EXTENDED_REPLY %s digest of %lu %s", digest_name,
    nblocks, nblocks == 1 ? "block" : "blocks");

  if (blocksz == 0) {
    data_len = st.st_blksize;

  } else {
    data_len = blocksz;
  }

  data = palloc(fxp->pool, data_len);

  while (TRUE) {
    pr_signals_handle();

    res = BIO_read(bio, data, data_len);
    if (res < 0) {
      if (BIO_should_read(bio)) {
        continue;
      }

      /* error */
      xerrno = errno;

      pr_fsio_close(fh);

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error reading from '%s': %s", path, strerror(xerrno));

      status_code = fxp_errno2status(xerrno, &reason);

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
        "('%s' [%d])", (unsigned long) status_code, reason,
        strerror(xerrno), xerrno);

      /* Since we already started writing the EXTENDED_REPLY, we have
       * to reset the pointers and overwrite the existing message.
       */
      buf = ptr;
      buflen = bufsz;

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        reason, NULL);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      /* Cleanup. */
      BIO_free(bio);

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
      EVP_MD_CTX_cleanup(pctx);
#else
      EVP_MD_CTX_free(pctx);
#endif /* prior to OpenSSL-1.1.0 */

      return fxp_packet_write(resp);

    } else if (res == 0) {
      if (BIO_should_retry(bio) != 0) {
        continue;
      }

      /* EOF */
      break;
    }

    if (blocksz != 0) {
      unsigned char digest[EVP_MAX_MD_SIZE];
      unsigned int digest_len = 0;

      EVP_DigestInit(pctx, md);
      EVP_DigestUpdate(pctx, data, res);
      EVP_DigestFinal(pctx, digest, &digest_len);

      sftp_msg_write_data(&buf, &buflen, digest, digest_len, FALSE);

      total_len += res; 
      if (len > 0 &&
          total_len >= len) {
        break;
      }
    }
  }

  if (blocksz == 0) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    EVP_DigestInit(pctx, md);
    EVP_DigestUpdate(pctx, data, res);
    EVP_DigestFinal(pctx, digest, &digest_len);

    sftp_msg_write_data(&buf, &buflen, digest, digest_len, FALSE);
  }

  /* Cleanup. */
  BIO_free(bio);
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    defined(HAVE_LIBRESSL)
  EVP_MD_CTX_cleanup(pctx);
#else
  EVP_MD_CTX_free(pctx);
#endif /* prior to OpenSSL-1.1.0 */
  pr_fsio_close(fh);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_copy_file(struct fxp_packet *fxp, char *src,
    char *dst, int overwrite) {
  char *abs_path, *args, *tmp;
  unsigned char *buf, *ptr;
  const char *reason;
  uint32_t buflen, bufsz, status_code;
  struct fxp_packet *resp;
  cmd_rec *cmd, *cmd2;
  int res, xerrno;
  struct stat st;

  args = pstrcat(fxp->pool, src, " ", dst, NULL);

  /* We need to provide an actual argv in this COPY cmd_rec, so we can't
   * use fxp_cmd_alloc(); we have to allocate the cmd_rec ourselves.
   */
  cmd = pr_cmd_alloc(fxp->pool, 4, pstrdup(fxp->pool, "SITE"),
    pstrdup(fxp->pool, "COPY"), src, dst);
  cmd->arg = pstrcat(fxp->pool, "COPY ", src, " ", dst, NULL);
  cmd->cmd_class = CL_WRITE;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "COPY of '%s' to '%s' blocked by '%s' handler", src, dst,
      (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  tmp = src;
  src = dir_best_path(fxp->pool, tmp);
  if (src == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "COPY request denied: unable to access path '%s'", tmp);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  tmp = dst;
  dst = dir_best_path(fxp->pool, tmp);
  if (dst == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "COPY request denied: unable to access path '%s'", tmp);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (strcmp(src, dst) == 0) {
    xerrno = EEXIST;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "COPY of '%s' to same path '%s', rejecting", src, dst);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_fs_clear_cache2(dst);
  res = pr_fsio_stat(dst, &st);
  if (res == 0) {
    unsigned char *allow_overwrite = NULL;
    int limit_allow;

    allow_overwrite = get_param_ptr(get_dir_ctxt(fxp->pool, dst),
      "AllowOverwrite", FALSE);

    cmd2 = pr_cmd_alloc(fxp->pool, 3, "SITE_COPY", src, dst);
    cmd2->arg = pstrdup(fxp->pool, args);
    limit_allow = dir_check(fxp->pool, cmd2, "WRITE", dst, NULL);

    if (!overwrite ||
        (allow_overwrite == NULL ||
         *allow_overwrite == FALSE) ||
        !limit_allow) {
      xerrno = EACCES;

      if (!overwrite) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "'%s' exists and client did not request COPY overwrites", dst);

      } else if (!limit_allow) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "COPY to '%s' blocked by <Limit> configuration", dst);

      } else {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "AllowOverwrite permission denied for '%s'", dst);
      }

      status_code = fxp_errno2status(xerrno, &reason);

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, reason);

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        reason, NULL);

      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      return fxp_packet_write(resp);
    }
  }

  if (fxp_path_pass_regex_filters(fxp->pool, "COPY", src) < 0 ||
      fxp_path_pass_regex_filters(fxp->pool, "COPY", dst) < 0) {
    xerrno = errno;

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  cmd2 = pr_cmd_alloc(fxp->pool, 3, "SITE_COPY", src, dst);
  cmd2->arg = pstrdup(fxp->pool, args);
  if (!dir_check(fxp->pool, cmd2, "READ", src, NULL)) {
    xerrno = EACCES;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "COPY of '%s' blocked by <Limit> configuration", src);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  res = pr_fs_copy_file2(src, dst, 0, NULL);
  if (res < 0) {
    xerrno = errno;

    status_code = fxp_errno2status(xerrno, &reason);

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error copying '%s' to '%s': %s", src, dst, strerror(xerrno));

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* No errors. */
  xerrno = errno = 0;

  pr_fs_clear_cache2(dst);
  pr_fsio_stat(dst, &st);

  fxp_cmd_dispatch(cmd);

  /* Write a TransferLog entry as well. */
  abs_path = sftp_misc_vroot_abs_path(fxp->pool, dst, TRUE);
  xferlog_write(0, session.c->remote_name, st.st_size, abs_path, 'b', 'i',
    'r', session.user, 'c', "_");

  status_code = fxp_errno2status(xerrno, &reason);

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, reason);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_fsync(struct fxp_packet *fxp,
    struct fxp_handle *fxh) {
  unsigned char *buf, *ptr;
  char *args;
  const char *path, *reason;
  uint32_t buflen, bufsz, status_code;
  struct fxp_packet *resp;
  cmd_rec *cmd;
  int res, xerrno;

  path = fxh->fh->fh_path;
  args = pstrdup(fxp->pool, path);

  cmd = fxp_cmd_alloc(fxp->pool, "FSYNC", args);
  cmd->cmd_class = CL_MISC|CL_SFTP;
  pr_cmd_dispatch_phase(cmd, PRE_CMD, 0);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  res = fsync(PR_FH_FD(fxh->fh));
  if (res < 0) {
    xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error calling fsync(2) on '%s': %s", path, strerror(xerrno));

    errno = xerrno;

  } else {
    /* No errors. */
    xerrno = errno = 0;
  }

  status_code = fxp_errno2status(xerrno, &reason);

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
    "('%s' [%d])", (unsigned long) status_code, reason,
    xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  if (xerrno == 0) {
    fxp_cmd_dispatch(cmd);

  } else {
    fxp_cmd_dispatch_err(cmd);
  }

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_hardlink(struct fxp_packet *fxp, char *src,
    char *dst) {
  unsigned char *buf, *ptr;
  char *args, *path;
  const char *reason;
  uint32_t buflen, bufsz, status_code;
  struct fxp_packet *resp;
  cmd_rec *cmd = NULL;
  int res, xerrno = 0;

  args = pstrcat(fxp->pool, src, " ", dst, NULL);

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "HARDLINK", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", args, NULL, NULL);

  pr_proctitle_set("%s - %s: HARDLINK %s %s", session.user, session.proc_prefix,
    src, dst);

  cmd = fxp_cmd_alloc(fxp->pool, "HARDLINK", args);
  cmd->cmd_class = CL_MISC|CL_SFTP;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  path = dir_best_path(fxp->pool, src);
  if (path == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "hardlink request denied: unable to access path '%s'", src);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }
  src = path;

  path = dir_best_path(fxp->pool, dst);
  if (path == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "hardlink request denied: unable to access path '%s'", dst);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }
  dst = path;

  if (!dir_check(fxp->pool, cmd, G_DIRS, src, NULL) ||
      !dir_check(fxp->pool, cmd, G_WRITE, dst, NULL)) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "HARDLINK of '%s' to '%s' blocked by <Limit> configuration",
      src, dst);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (strcmp(src, dst) == 0) {
    xerrno = EEXIST;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "HARDLINK of '%s' to same path '%s', rejecting", src, dst);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxp_path_pass_regex_filters(fxp->pool, "HARDLINK", src) < 0 ||
      fxp_path_pass_regex_filters(fxp->pool, "HARDLINK", dst) < 0) {
    xerrno = errno;

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  res = pr_fsio_link(src, dst);
  if (res < 0) {
    xerrno = errno;

    (void) pr_trace_msg("fileperms", 1, "HARDLINK, user '%s' (UID %s, "
      "GID %s): error hardlinking '%s' to '%s': %s", session.user,
      pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
      src, dst, strerror(xerrno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error hardlinking '%s' to '%s': %s", src, dst, strerror(xerrno));

    errno = xerrno;

  } else {
    /* No errors. */
    xerrno = errno = 0;
  }

  status_code = fxp_errno2status(xerrno, &reason);

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
    "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
    xerrno);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  if (xerrno == 0) {
    fxp_cmd_dispatch(cmd);

  } else {
    fxp_cmd_dispatch_err(cmd);
  }

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_posix_rename(struct fxp_packet *fxp, char *src,
    char *dst) {
  unsigned char *buf, *ptr;
  char *args;
  const char *reason;
  uint32_t buflen, bufsz, status_code;
  struct fxp_packet *resp;
  cmd_rec *cmd = NULL, *cmd2 = NULL, *cmd3 = NULL;
  int res, xerrno = 0;

  args = pstrcat(fxp->pool, src, " ", dst, NULL);

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "RENAME", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", args, NULL, NULL);

  pr_proctitle_set("%s - %s: RENAME %s %s", session.user, session.proc_prefix,
    src, dst);

  cmd = fxp_cmd_alloc(fxp->pool, "RENAME", args);
  cmd->cmd_class = CL_MISC|CL_SFTP;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  cmd2 = fxp_cmd_alloc(fxp->pool, C_RNFR, src);
  cmd2->cmd_class = CL_MISC|CL_WRITE;
  if (pr_cmd_dispatch_phase(cmd2, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RENAME from '%s' blocked by '%s' handler", src, (char *) cmd2->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  src = dir_best_path(fxp->pool, cmd2->arg);
  if (src == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "posix-rename request denied: unable to access path '%s'", cmd2->arg);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (pr_table_add(session.notes, "mod_core.rnfr-path",
      pstrdup(session.pool, src), 0) < 0) {
    if (errno != EEXIST) {
      pr_trace_msg(trace_channel, 8,
        "error setting 'mod_core.rnfr-path' note: %s", strerror(errno));
    }
  }

  cmd3 = fxp_cmd_alloc(fxp->pool, C_RNTO, dst);
  cmd3->cmd_class = CL_MISC|CL_WRITE;
  if (pr_cmd_dispatch_phase(cmd3, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RENAME to '%s' blocked by '%s' handler", dst, (char *) cmd3->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd3);

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  dst = dir_best_path(fxp->pool, cmd3->arg);
  if (dst == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "posix-rename request denied: unable to access path '%s'", cmd2->arg);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd3);

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (!dir_check(fxp->pool, cmd2, G_DIRS, src, NULL) ||
      !dir_check(fxp->pool, cmd3, G_WRITE, dst, NULL)) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RENAME of '%s' to '%s' blocked by <Limit> configuration",
      src, dst);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd3);

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (strcmp(src, dst) == 0) {
    xerrno = EEXIST;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RENAME of '%s' to same path '%s', rejecting", src, dst);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(EEXIST));
    fxp_cmd_dispatch_err(cmd3);

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(EEXIST));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxp_path_pass_regex_filters(fxp->pool, "RENAME", src) < 0 ||
      fxp_path_pass_regex_filters(fxp->pool, "RENAME", dst) < 0) {
    xerrno = errno;

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd3);

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  res = pr_fsio_rename(src, dst);
  if (res < 0) {
    if (errno != EXDEV) {
      xerrno = errno;

      (void) pr_trace_msg("fileperms", 1, "RENAME, user '%s' (UID %s, "
        "GID %s): error renaming '%s' to '%s': %s", session.user,
        pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
        src, dst, strerror(xerrno));

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error renaming '%s' to '%s': %s", src, dst, strerror(xerrno));

      errno = xerrno;

    } else {
      /* In this case, we should manually copy the file from the source
       * path to the destination path.
       */
      errno = 0;

      res = pr_fs_copy_file2(src, dst, 0, NULL);
      if (res < 0) {
        xerrno = errno;

        (void) pr_trace_msg("fileperms", 1, "RENAME, user '%s' (UID %s, "
          "GID %s): error copying '%s' to '%s': %s", session.user,
          pr_uid2str(fxp->pool, session.uid),
          pr_gid2str(fxp->pool, session.gid),
          src, dst, strerror(xerrno));

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error copying '%s' to '%s': %s", src, dst, strerror(xerrno));

        errno = xerrno;

      } else {
        /* Once copied, remove the original path. */
        if (pr_fsio_unlink(src) < 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error deleting '%s': %s", src, strerror(errno));
        }

        xerrno = errno = 0;
      }
    }

  } else {
    /* No errors. */
    xerrno = errno = 0;
  }

  status_code = fxp_errno2status(xerrno, &reason);

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
    "('%s' [%d])", (unsigned long) status_code, reason,
    xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

  /* Clear out any transfer-specific data. */
  if (session.xfer.p) {
    destroy_pool(session.xfer.p);
  }
  memset(&session.xfer, 0, sizeof(session.xfer));

  /* The timing of these steps may look peculiar, but it's deliberate,
   * in order to get the expected log messages in an ExtendedLog.
   */

  session.xfer.p = make_sub_pool(fxp_pool);
  pr_pool_tag(session.xfer.p, "SFTP session transfer pool");
  memset(&session.xfer.start_time, 0, sizeof(session.xfer.start_time));
  gettimeofday(&session.xfer.start_time, NULL);

  session.xfer.path = pstrdup(session.xfer.p, src);

  if (xerrno == 0) {
    pr_response_add(R_350,
      "File or directory exists, ready for destination name");
    fxp_cmd_dispatch(cmd2);

  } else {
    pr_response_add_err(R_550, "%s: %s", (char *) cmd2->argv[0],
      strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);
  }

  session.xfer.path = pstrdup(session.xfer.p, dst);

  if (xerrno == 0) {
    pr_response_add(R_250, "Rename successful");
    fxp_cmd_dispatch(cmd3);

  } else {
    pr_response_add_err(R_550, "%s: %s", (char *) cmd3->argv[0],
      strerror(xerrno));
    fxp_cmd_dispatch_err(cmd3);
  }

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);
  if (xerrno == 0) {
    fxp_cmd_dispatch(cmd);

  } else {
    fxp_cmd_dispatch_err(cmd);
  }

  /* Clear out any transfer-specific data. */
  if (session.xfer.p) {
    destroy_pool(session.xfer.p);
  }
  memset(&session.xfer, 0, sizeof(session.xfer));

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

#ifdef HAVE_SYS_STATVFS_H

static off_t get_fs_bytes_total(void *ptr) {
# if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64 && \
   defined(SOLARIS2) && !defined(SOLARIS2_5_1) && !defined(SOLARIS2_6) && \
   !defined(SOLARIS2_7)
  /* Note: somewhere along the way, Sun decided that the prototype for
   * its statvfs64(2) function would include a statvfs64_t rather than
   * struct statvfs64.  In 2.6 and 2.7, it's struct statvfs64, and
   * in 8, 9 it's statvfs64_t.  This should silence compiler warnings.
   * (The statvfs_t will be redefined to a statvfs64_t as appropriate on
   * LFS systems).
   */
  statvfs_t *fs = ptr;
#  else
  struct statvfs *fs = ptr;
# endif /* LFS && !Solaris 2.5.1 && !Solaris 2.6 && !Solaris 2.7 */

  return ((off_t) fs->f_blocks * (off_t) fs->f_frsize);
}

static off_t get_fs_bytes_unused(void *ptr) {
# if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64 && \
   defined(SOLARIS2) && !defined(SOLARIS2_5_1) && !defined(SOLARIS2_6) && \
   !defined(SOLARIS2_7)
  /* Note: somewhere along the way, Sun decided that the prototype for
   * its statvfs64(2) function would include a statvfs64_t rather than
   * struct statvfs64.  In 2.6 and 2.7, it's struct statvfs64, and
   * in 8, 9 it's statvfs64_t.  This should silence compiler warnings.
   * (The statvfs_t will be redefined to a statvfs64_t as appropriate on
   * LFS systems).
   */
  statvfs_t *fs = ptr;
#  else
  struct statvfs *fs = ptr;
# endif /* LFS && !Solaris 2.5.1 && !Solaris 2.6 && !Solaris 2.7 */

  return ((off_t) fs->f_bavail * (off_t) fs->f_frsize);
}

static off_t get_user_bytes_avail(void *ptr) {
# if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64 && \
   defined(SOLARIS2) && !defined(SOLARIS2_5_1) && !defined(SOLARIS2_6) && \
   !defined(SOLARIS2_7)
  /* Note: somewhere along the way, Sun decided that the prototype for
   * its statvfs64(2) function would include a statvfs64_t rather than
   * struct statvfs64.  In 2.6 and 2.7, it's struct statvfs64, and
   * in 8, 9 it's statvfs64_t.  This should silence compiler warnings.
   * (The statvfs_t will be redefined to a statvfs64_t as appropriate on
   * LFS systems).
   */
  statvfs_t *fs = ptr;
#  else
  struct statvfs *fs = ptr;
# endif /* LFS && !Solaris 2.5.1 && !Solaris 2.6 && !Solaris 2.7 */

  /* XXX This should use mod_quotatab as well, for user-specific limits/
   * tallies.
   */

  /* Take the total number of blocks, and subtract the difference between
   * the total free blocks and the non-root free blocks.  That difference
   * provides the number of blocks reserved for root.  So subtracting those
   * reserved blocks from the total blocks yields the user-available blocks.
   */
  return (((off_t) fs->f_blocks - ((off_t) fs->f_bfree) - (off_t) fs->f_bavail) * (off_t) fs->f_frsize);
}

static off_t get_user_bytes_unused(void *ptr) {
# if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64 && \
   defined(SOLARIS2) && !defined(SOLARIS2_5_1) && !defined(SOLARIS2_6) && \
   !defined(SOLARIS2_7)
  /* Note: somewhere along the way, Sun decided that the prototype for
   * its statvfs64(2) function would include a statvfs64_t rather than
   * struct statvfs64.  In 2.6 and 2.7, it's struct statvfs64, and
   * in 8, 9 it's statvfs64_t.  This should silence compiler warnings.
   * (The statvfs_t will be redefined to a statvfs64_t as appropriate on
   * LFS systems).
   */
  statvfs_t *fs = ptr;
#  else
  struct statvfs *fs = ptr;
# endif /* LFS && !Solaris 2.5.1 && !Solaris 2.6 && !Solaris 2.7 */

  /* XXX This should use mod_quotatab as well, for user-specific limits/
   * tallies.
   */

  return ((off_t) fs->f_bavail * (off_t) fs->f_frsize);
}

static int fxp_handle_ext_space_avail(struct fxp_packet *fxp, char *path) {
  unsigned char *buf, *ptr;
  const char *reason;
  uint32_t buflen, bufsz, status_code;
  struct fxp_packet *resp;

# if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64 && \
   defined(SOLARIS2) && !defined(SOLARIS2_5_1) && !defined(SOLARIS2_6) && \
   !defined(SOLARIS2_7)
  /* Note: somewhere along the way, Sun decided that the prototype for
   * its statvfs64(2) function would include a statvfs64_t rather than
   * struct statvfs64.  In 2.6 and 2.7, it's struct statvfs64, and
   * in 8, 9 it's statvfs64_t.  This should silence compiler warnings.
   * (The statvfs_t will be redefined to a statvfs64_t as appropriate on
   * LFS systems).
   */
  statvfs_t fs;
#  else
  struct statvfs fs;
# endif /* LFS && !Solaris 2.5.1 && !Solaris 2.6 && !Solaris 2.7 */

  pr_trace_msg(trace_channel, 8, "client sent space-available request: "
    "path = '%s'", path);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  if (statvfs(path, &fs) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "statvfs() error using '%s': %s",
      path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8,
    "sending response: EXTENDED_REPLY <space-avail data of '%s'>", path);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_EXTENDED_REPLY);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);

  /* Total bytes on device */
  sftp_msg_write_long(&buf, &buflen, (uint64_t) get_fs_bytes_total(&fs));

  /* Unused bytes on device. */
  sftp_msg_write_long(&buf, &buflen, (uint64_t) get_fs_bytes_unused(&fs));

  /* Total bytes available to user. */
  sftp_msg_write_long(&buf, &buflen, (uint64_t) get_user_bytes_avail(&fs));

  /* Unused bytes available to user. */
  sftp_msg_write_long(&buf, &buflen, (uint64_t) get_user_bytes_unused(&fs));

  sftp_msg_write_int(&buf, &buflen, (uint32_t) fs.f_frsize);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_statvfs(struct fxp_packet *fxp, const char *path) {
  unsigned char *buf, *ptr;
  const char *reason;
  uint32_t buflen, bufsz, status_code;
  struct fxp_packet *resp;
  uint64_t fs_id = 0, fs_flags = 0;

# if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64 && \
   defined(SOLARIS2) && !defined(SOLARIS2_5_1) && !defined(SOLARIS2_6) && \
   !defined(SOLARIS2_7)
  /* Note: somewhere along the way, Sun decided that the prototype for
   * its statvfs64(2) function would include a statvfs64_t rather than
   * struct statvfs64.  In 2.6 and 2.7, it's struct statvfs64, and
   * in 8, 9 it's statvfs64_t.  This should silence compiler warnings.
   * (The statvfs_t will be redefined to a statvfs64_t as appropriate on
   * LFS systems).
   */
  statvfs_t fs;
#  else
  struct statvfs fs;
# endif /* LFS && !Solaris 2.5.1 && !Solaris 2.6 && !Solaris 2.7 */

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  if (statvfs(path, &fs) < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "statvfs() error using '%s': %s",
      path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8,
    "sending response: EXTENDED_REPLY <statvfs data of '%s'>", path);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_EXTENDED_REPLY);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);
  sftp_msg_write_long(&buf, &buflen, fs.f_bsize);
  sftp_msg_write_long(&buf, &buflen, fs.f_frsize);
  sftp_msg_write_long(&buf, &buflen, fs.f_blocks);
  sftp_msg_write_long(&buf, &buflen, fs.f_bfree);
  sftp_msg_write_long(&buf, &buflen, fs.f_bavail);
  sftp_msg_write_long(&buf, &buflen, fs.f_files);
  sftp_msg_write_long(&buf, &buflen, fs.f_ffree);
  sftp_msg_write_long(&buf, &buflen, fs.f_favail);

  /* AIX requires this machination because a) its statvfs struct has
   * non-standard data types for the fsid value:
   *
   *  https://lists.dulug.duke.edu/pipermail/rpm-devel/2006-July/001236.html
   *  https://lists.dulug.duke.edu/pipermail/rpm-devel/2006-July/001264.html
   *  https://lists.dulug.duke.edu/pipermail/rpm-devel/2006-July/001265.html
   *  https://lists.dulug.duke.edu/pipermail/rpm-devel/2006-July/001268.html
   *
   * and b) it does not really matter what value is written; the client is
   * not going to be able to do much with this value anyway.  From that
   * perspective, I'm not sure why the OpenSSH extension even includes the
   * value in the response (*shrug*).
   */
#if !defined(AIX4) && !defined(AIX5)
  memcpy(&fs_id, &(fs.f_fsid), sizeof(fs_id));
#endif
  sftp_msg_write_long(&buf, &buflen, fs_id);

  /* These flags and values are defined by OpenSSH's PROTOCOL document.
   *
   * Other platforms support more fs.f_flag values than just ST_RDONLY
   * and ST_NOSUID, but those are the only two flags handled by OpenSSH;
   * thus we cannot simply send fs.f_flag directly to the client as is.
   */
#ifdef ST_RDONLY
  if (fs.f_flag & ST_RDONLY) {
    fs_flags |= SSH2_FXE_STATVFS_ST_RDONLY;
  }
#endif

#ifdef ST_NOSUID
  if (fs.f_flag & ST_NOSUID) {
    fs_flags |= SSH2_FXE_STATVFS_ST_NOSUID;
  }
#endif

  sftp_msg_write_long(&buf, &buflen, fs_flags);
  sftp_msg_write_long(&buf, &buflen, fs.f_namemax);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}
#endif /* !HAVE_SYS_STATVFS_H */

#ifdef PR_USE_XATTR
static int fxp_handle_ext_getxattr(struct fxp_packet *fxp, const char *path,
    const char *name, uint32_t valsz) {
  ssize_t res;
  void *val;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, status_code;
  const char *reason;
  struct fxp_packet *resp;

  val = pcalloc(fxp->pool, (size_t) valsz+1);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ + valsz;
  buf = ptr = palloc(fxp->pool, bufsz);

  res = pr_fsio_lgetxattr(fxp->pool, path, name, val, (size_t) valsz);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "getxattr(2) error on '%s' for attribute '%s': %s", path, name,
      strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8,
    "sending response: EXTENDED_REPLY (%lu bytes)", (unsigned long) res);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_EXTENDED_REPLY);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);
  sftp_msg_write_data(&buf, &buflen, val, res, TRUE);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_fgetxattr(struct fxp_packet *fxp, const char *handle,
    const char *name, uint32_t valsz) {
  ssize_t res;
  void *val;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, status_code;
  const char *path, *reason;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ + valsz;
  buf = ptr = palloc(fxp->pool, bufsz);

  fxh = fxp_handle_get(handle);
  if (fxh == NULL) {
    pr_trace_msg(trace_channel, 17,
      "fgetxattr@proftpd.org: unable to find handle for name '%s': %s", handle,
      strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->dirh != NULL) {
    /* Request for extended attributes on a directory handle.  It's not
     * easy to get the file descriptor on a directory, so we'll just do
     * by path instead.
     */
    return fxp_handle_ext_getxattr(fxp, fxh->fh->fh_path, name, valsz);
  }

  if (fxh->fh == NULL) {
    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  path = fxh->fh->fh_path;
  val = pcalloc(fxp->pool, (size_t) valsz+1);

  res = pr_fsio_fgetxattr(fxp->pool, fxh->fh, name, val, (size_t) valsz);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "fgetxattr(2) error on '%s' for attribute '%s': %s", path, name,
      strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8,
    "sending response: EXTENDED_REPLY (%lu bytes)", (unsigned long) res);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_EXTENDED_REPLY);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);
  sftp_msg_write_data(&buf, &buflen, val, res, TRUE);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_listxattr(struct fxp_packet *fxp, const char *path) {
  register unsigned int i;
  int res;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, status_code;
  const char *reason;
  struct fxp_packet *resp;
  array_header *names = NULL;

  buflen = bufsz = FXP_RESPONSE_NAME_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  res = pr_fsio_llistxattr(fxp->pool, path, &names);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "listxattr(2) error on '%s': %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8,
    "sending response: EXTENDED_REPLY (%d attribute names)", names->nelts);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_EXTENDED_REPLY);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);
  sftp_msg_write_int(&buf, &buflen, names->nelts);
  for (i = 0; i < names->nelts; i++) {
    const char *name;

    name = ((const char **) names->elts)[i];
    sftp_msg_write_string(&buf, &buflen, name);
  }

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_flistxattr(struct fxp_packet *fxp,
    const char *handle) {
  register unsigned int i;
  int res;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, status_code;
  const char *path, *reason;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  array_header *names = NULL;

  buflen = bufsz = FXP_RESPONSE_NAME_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  fxh = fxp_handle_get(handle);
  if (fxh == NULL) {
    pr_trace_msg(trace_channel, 17,
      "flistxattr@proftpd.org: unable to find handle for name '%s': %s", handle,
      strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->dirh != NULL) {
    /* Request for extended attributes on a directory handle.  It's not
     * easy to get the file descriptor on a directory, so we'll just do
     * by path instead.
     */
    return fxp_handle_ext_listxattr(fxp, fxh->fh->fh_path);
  }

  if (fxh->fh == NULL) {
    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  path = fxh->fh->fh_path;
  res = pr_fsio_flistxattr(fxp->pool, fxh->fh, &names);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "flistxattr(2) error on '%s': %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8,
    "sending response: EXTENDED_REPLY (%d attributes)", names->nelts);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_EXTENDED_REPLY);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);
  sftp_msg_write_int(&buf, &buflen, names->nelts);
  for (i = 0; i < names->nelts; i++) {
    const char *name;

    name = ((const char **) names->elts)[i];
    sftp_msg_write_string(&buf, &buflen, name);
  }

  sftp_msg_write_data(&buf, &buflen, (const unsigned char *) names, res, TRUE);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_removexattr(struct fxp_packet *fxp, const char *path,
    const char *name) {
  int res;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, status_code;
  const char *reason;
  struct fxp_packet *resp;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  res = pr_fsio_lremovexattr(fxp->pool, path, name);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "removexattr(2) error on '%s' for attribute '%s': %s", path, name,
      strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  status_code = SSH2_FX_OK;
  reason = "OK";

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, reason);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_fremovexattr(struct fxp_packet *fxp,
    const char *handle, const char *name) {
  int res;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, status_code;
  const char *path, *reason;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  fxh = fxp_handle_get(handle);
  if (fxh == NULL) {
    pr_trace_msg(trace_channel, 17,
      "fremovexattr@proftpd.org: unable to find handle for name '%s': %s",
      handle, strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->dirh != NULL) {
    /* Request for extended attributes on a directory handle.  It's not
     * easy to get the file descriptor on a directory, so we'll just do
     * by path instead.
     */
    return fxp_handle_ext_removexattr(fxp, fxh->fh->fh_path, name);
  }

  if (fxh->fh == NULL) {
    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  path = fxh->fh->fh_path;

  res = pr_fsio_fremovexattr(fxp->pool, fxh->fh, name);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "fremovexattr(2) error on '%s' for attribute '%s': %s", path, name,
      strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  status_code = SSH2_FX_OK;
  reason = "OK";

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, reason);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_setxattr(struct fxp_packet *fxp, const char *path,
    const char *name, void *val, uint32_t valsz, uint32_t pflags) {
  int res, flags = 0;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, status_code;
  const char *reason;
  struct fxp_packet *resp;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  if (pflags & SSH2_FXE_XATTR_CREATE) {
    flags |= PR_FSIO_XATTR_FL_CREATE;
  }

  if (pflags & SSH2_FXE_XATTR_REPLACE) {
    flags |= PR_FSIO_XATTR_FL_REPLACE;
  }

  res = pr_fsio_lsetxattr(fxp->pool, path, name, val, (size_t) valsz, flags);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "setxattr(2) error on '%s' for attribute '%s': %s", path, name,
      strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  status_code = SSH2_FX_OK;
  reason = "OK";

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, reason);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_fsetxattr(struct fxp_packet *fxp, const char *handle,
    const char *name, void *val, uint32_t valsz, uint32_t pflags) {
  int res, flags = 0;
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, status_code;
  const char *path, *reason;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  fxh = fxp_handle_get(handle);
  if (fxh == NULL) {
    pr_trace_msg(trace_channel, 17,
      "fsetxattr@proftpd.org: unable to find handle for name '%s': %s", handle,
      strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->dirh != NULL) {
    /* Request for extended attributes on a directory handle.  It's not
     * easy to get the file descriptor on a directory, so we'll just do
     * by path instead.
     */
    return fxp_handle_ext_setxattr(fxp, fxh->fh->fh_path, name, val, valsz,
      pflags);
  }

  if (fxh->fh == NULL) {
    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (pflags & SSH2_FXE_XATTR_CREATE) {
    flags |= PR_FSIO_XATTR_FL_CREATE;
  }

  if (pflags & SSH2_FXE_XATTR_REPLACE) {
    flags |= PR_FSIO_XATTR_FL_REPLACE;
  }

  path = fxh->fh->fh_path;

  res = pr_fsio_fsetxattr(fxp->pool, fxh->fh, name, val, (size_t) valsz, flags);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "fsetxattr(2) error on '%s' for attribute '%s': %s", path, name,
      strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  status_code = SSH2_FX_OK;
  reason = "OK";

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, reason);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}
#endif /* PR_USE_XATTR */

static int fxp_handle_ext_vendor_id(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *vendor_name, *product_name, *product_version;
  uint32_t buflen, bufsz, status_code;
  uint64_t build_number;
  const char *reason;
  struct fxp_packet *resp;

  vendor_name = sftp_msg_read_string(fxp->pool, &fxp->payload,
    &fxp->payload_sz);

  product_name = sftp_msg_read_string(fxp->pool, &fxp->payload,
    &fxp->payload_sz);

  product_version = sftp_msg_read_string(fxp->pool, &fxp->payload,
    &fxp->payload_sz);

  build_number = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);

  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    vendor_name = sftp_utf8_decode_str(fxp->pool, vendor_name);
    product_name = sftp_utf8_decode_str(fxp->pool, product_name);
    product_version = sftp_utf8_decode_str(fxp->pool, product_version);
  }

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "client sent 'vendor-id' extension: { vendorName = '%s', "
    "productName = '%s', productVersion = '%s', buildNumber = %" PR_LU " }",
    vendor_name, product_name, product_version, (pr_off_t) build_number);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  status_code = SSH2_FX_OK;
  reason = "OK";

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, reason);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_ext_version_select(struct fxp_packet *fxp,
    char *version_str) {
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz, status_code;
  const char *reason;
  struct fxp_packet *resp;
  int res = 0, val = 0;
  unsigned int version = 0;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  if (!allow_version_select) {
    int xerrno = EACCES;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client sent 'version-select' request at inappropriate time, rejecting");

    status_code = SSH2_FX_FAILURE;
    reason = "Failure";

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    (void) fxp_packet_write(resp);

    errno = EINVAL;
    return -1;
  }

  val = atoi(version_str);
  if (val < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested invalid SFTP protocol version %d via 'version-select'",
      val);
    res = -1;
  }

  version = val;

  if (res == 0 &&
      version > fxp_max_client_version) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested SFTP protocol version %u via 'version-select', "
      "which exceeds SFTPClientMatch max SFTP protocol version %u, rejecting",
      version, fxp_max_client_version);
    res = -1;
  }

  if (res == 0 &&
      version < fxp_min_client_version) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested SFTP protocol version %u via 'version-select', "
      "which is less than SFTPClientMatch min SFTP protocol version %u, "
      "rejecting", version, fxp_min_client_version);
    res = -1;
  }

#ifndef PR_USE_NLS
  /* If NLS supported was enabled in the proftpd build, then we can support
   * UTF8, and thus every other version of SFTP.  Otherwise, we can only
   * support up to version 3.
   */
  if (res == 0 &&
      version > 3) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested SFTP protocol version %u via 'version-select', "
      "but we can only support protocol version 3 due to lack of "
      "UTF8 support (requires --enable-nls)", version);
    res = -1;
  }
#endif

  if (res < 0) {
    int xerrno = EINVAL;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client sent 'version-select' request at inappropriate time, rejecting");

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    (void) fxp_packet_write(resp);

    errno = EINVAL;
    return -1;
  }

  pr_trace_msg(trace_channel, 7, "client requested switch to SFTP protocol "
    "version %u via 'version-select'", version);
  fxp_session->client_version = (unsigned long) version;

  status_code = SSH2_FX_OK;
  reason = "OK";

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, reason);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  allow_version_select = FALSE;
  return fxp_packet_write(resp);
}

/* Request handlers */

static int fxp_handle_close(struct fxp_packet *fxp) {
  int xerrno = 0, res = 0, xfer_direction = 0;
  unsigned char *buf, *ptr;
  char *name, *xfer_filename = NULL, *xfer_path = NULL;
  const char *reason;
  uint32_t buflen, bufsz, status_code;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  cmd_rec *cmd;
  struct timeval xfer_start_time;
  off_t xfer_file_size = 0, xfer_total_bytes = 0;

  xfer_start_time.tv_sec = xfer_start_time.tv_usec = 0;

  name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

  cmd = fxp_cmd_alloc(fxp->pool, "CLOSE", name);

  /* Set the command class to MISC for now; we'll change it later to
   * READ or WRITE once we know which it is.
   */
  cmd->cmd_class = CL_MISC|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "CLOSE", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", name, NULL, NULL);

  pr_proctitle_set("%s - %s: CLOSE %s", session.user, session.proc_prefix,
    name);

  pr_trace_msg(trace_channel, 7, "received request: CLOSE %s", name);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  fxh = fxp_handle_get(name);
  if (fxh == NULL) {
    pr_trace_msg(trace_channel, 17,
      "%s: unable to find handle for name '%s': %s", (char *) cmd->argv[0],
      name, strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->dirh == NULL &&
      fxh->fh == NULL) {
    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);
 
    fxp_handle_delete(fxh);
    destroy_pool(fxh->pool);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  /* Add a note containing the file handle for logging (Bug#3707). */
  fxp_set_filehandle_note(cmd, fxh);

  pr_timer_remove(PR_TIMER_STALLED, ANY_MODULE);

  if (fxh->fh != NULL) {
    char *curr_path = NULL, *real_path = NULL;
    cmd_rec *cmd2 = NULL;

    curr_path = pstrdup(fxp->pool, fxh->fh->fh_path);
    real_path = curr_path;

    if (fxh->fh_real_path) {
      real_path = fxh->fh_real_path;
    }

    /* Set session.curr_cmd appropriately here, for any FSIO callbacks. */ 
    if (fxh->fh_flags & O_APPEND) {
      cmd->cmd_class &= ~CL_MISC;
      cmd->cmd_class |= CL_WRITE;
      session.curr_cmd = C_APPE;

    } else if ((fxh->fh_flags & O_WRONLY) ||
               (fxh->fh_flags & O_RDWR)) {
      cmd->cmd_class &= ~CL_MISC;
      cmd->cmd_class |= CL_WRITE;
      session.curr_cmd = C_STOR;

    } else if (fxh->fh_flags == O_RDONLY) {
      cmd->cmd_class &= ~CL_MISC;
      cmd->cmd_class |= CL_READ;
      session.curr_cmd = C_RETR;
    }

    res = pr_fsio_close(fxh->fh);
    xerrno = errno;

    session.curr_cmd = "CLOSE";

    pr_scoreboard_entry_update(session.pid,
      PR_SCORE_CMD_ARG, "%s", real_path, NULL, NULL);

    if (fxh->fh_real_path != NULL &&
        res == 0) {
      /* This is a HiddenStores file, and needs to be renamed to the real
       * path.
       */

      pr_trace_msg(trace_channel, 8, "renaming HiddenStores path '%s' to '%s'",
        curr_path, real_path);

      res = pr_fsio_rename(curr_path, real_path);
      if (res < 0) {
        xerrno = errno;

        pr_log_pri(PR_LOG_WARNING, "Rename of %s to %s failed: %s",
          curr_path, real_path, strerror(xerrno));

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "renaming of HiddenStore path '%s' to '%s' failed: %s",
          curr_path, real_path, strerror(xerrno));

        pr_fsio_unlink(curr_path);
      }
    }

    if (fxh->fh_flags & O_APPEND) {
      cmd2 = fxp_cmd_alloc(fxp->pool, C_APPE, pstrdup(fxp->pool, real_path));
      cmd2->cmd_id = pr_cmd_get_id(C_APPE);

      if (pr_table_add(cmd2->notes, "mod_xfer.store-path",
          pstrdup(fxp->pool, real_path), 0) < 0) {
        if (errno != EEXIST) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error adding 'mod_xfer.store-path' note: %s", strerror(errno));
        }
      }

    } else if ((fxh->fh_flags & O_WRONLY) ||
               (fxh->fh_flags & O_RDWR)) {
      cmd2 = fxp_cmd_alloc(fxp->pool, C_STOR, pstrdup(fxp->pool, real_path));
      cmd2->cmd_id = pr_cmd_get_id(C_STOR);

      if (pr_table_add(cmd2->notes, "mod_xfer.store-path",
          pstrdup(fxp->pool, real_path), 0) < 0) {
        if (errno != EEXIST) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error adding 'mod_xfer.store-path' note: %s", strerror(errno));
        }
      }

    } else if (fxh->fh_flags == O_RDONLY) {
      cmd2 = fxp_cmd_alloc(fxp->pool, C_RETR, pstrdup(fxp->pool, real_path));
      cmd2->cmd_id = pr_cmd_get_id(C_RETR);

      if (pr_table_add(cmd2->notes, "mod_xfer.retr-path",
          pstrdup(fxp->pool, real_path), 0) < 0) {
        if (errno != EEXIST) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error adding 'mod_xfer.retr-path' note: %s", strerror(errno));
        }
      }
    }

    fxh->fh = NULL;

    /* Before we dispatch to the RETR/STOR handlers, make a copy of the
     * session.xfer.path variable (and others).  The RETR/STOR handlers will
     * clear out the session.xfer.p pool, but we will want to put that path
     * back, after the RETR/STOR handlers, for the sake of logging e.g. a %f
     * LogFormat variable for the CLOSE request.
     */

    xfer_direction = session.xfer.direction;
    xfer_filename = pstrdup(fxp->pool, session.xfer.filename);
    xfer_path = pstrdup(fxp->pool, session.xfer.path);
    memcpy(&xfer_start_time, &(session.xfer.start_time),
      sizeof(struct timeval));
    xfer_file_size = session.xfer.file_size;
    xfer_total_bytes = session.xfer.total_bytes;

    if (cmd2) {
      if (fxh->fh_existed &&
          (pr_cmd_cmp(cmd2, PR_CMD_STOR_ID) == 0 ||
           pr_cmd_cmp(cmd2, PR_CMD_APPE_ID) == 0)) {

        /* Clear any existing key in the notes. */
        (void) pr_table_remove(cmd->notes, "mod_xfer.file-modified", NULL);

        if (pr_table_add(cmd->notes, "mod_xfer.file-modified",
            pstrdup(cmd->pool, "true"), 0) < 0) {
          if (errno != EEXIST) {
            pr_log_pri(PR_LOG_NOTICE,
              "notice: error adding 'mod_xfer.file-modified' note: %s",
              strerror(errno));
          }
        }

        /* Clear any existing key in the notes. */
        (void) pr_table_remove(cmd2->notes, "mod_xfer.file-modified", NULL);

        if (pr_table_add(cmd2->notes, "mod_xfer.file-modified",
            pstrdup(cmd2->pool, "true"), 0) < 0) {
          if (errno != EEXIST) {
            pr_log_pri(PR_LOG_NOTICE,
              "notice: error adding 'mod_xfer.file-modified' note: %s",
              strerror(errno));
          }
        }
      }

      if (res < 0 &&
          xerrno != EOF) {

        pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
        fxp_cmd_dispatch_err(cmd2);

      } else {
        pr_response_add(R_226, "%s", "Transfer complete");
        session.xfer.path = sftp_misc_vroot_abs_path(cmd2->pool,
          session.xfer.path, FALSE);
        fxp_cmd_dispatch(cmd2);
      }
    }

  } else if (fxh->dirh != NULL) {
    cmd_rec *cmd2;

    cmd2 = fxp_cmd_alloc(fxp->pool, C_MLSD, (char *) fxh->dir);
    cmd2->cmd_class = CL_DIRS;
    cmd2->cmd_id = pr_cmd_get_id(C_MLSD);

    pr_scoreboard_entry_update(session.pid,
      PR_SCORE_CMD_ARG, "%s", fxh->dir, NULL, NULL);

    res = pr_fsio_closedir(fxh->dirh);
    if (res < 0) {
      xerrno = errno;

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error closing directory '%s': %s", fxh->dir, strerror(xerrno));
      fxp_cmd_dispatch_err(cmd2);

    } else {
      fxp_cmd_dispatch(cmd2);
    }

    fxh->dirh = NULL;
  }

  if (res < 0) {
    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

  } else {
    errno = 0;
    status_code = fxp_errno2status(0, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);
  }

  fxp_handle_delete(fxh);
  destroy_pool(fxh->pool);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  /* Now re-populate the session.xfer struct, for mod_log's handling of
   * the CLOSE request.
   */
  if (session.xfer.p) {
    destroy_pool(session.xfer.p);
  }

  session.xfer.p = fxp->pool;
  session.xfer.direction = xfer_direction;
  session.xfer.filename = xfer_filename;
  session.xfer.path = xfer_path;
  memcpy(&(session.xfer.start_time), &xfer_start_time, sizeof(struct timeval));
  session.xfer.file_size = xfer_file_size;
  session.xfer.total_bytes = xfer_total_bytes;

  if (res < 0) {
    fxp_cmd_dispatch_err(cmd);

  } else {
    fxp_cmd_dispatch(cmd);
  }

  /* Clear out session.xfer again. */
  memset(&session.xfer, 0, sizeof(session.xfer));

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);
  
  return fxp_packet_write(resp);
}

static int fxp_handle_extended(struct fxp_packet *fxp) {
  int res;
  unsigned char *buf, *ptr;
  char *ext_request_name;
  uint32_t buflen, bufsz, status_code;
  struct fxp_packet *resp;
  cmd_rec *cmd;

  ext_request_name = sftp_msg_read_string(fxp->pool, &fxp->payload,
    &fxp->payload_sz);

  cmd = fxp_cmd_alloc(fxp->pool, "EXTENDED", ext_request_name);
  cmd->cmd_class = CL_MISC|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "EXTENDED", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", ext_request_name, NULL, NULL);

  pr_proctitle_set("%s - %s: EXTENDED %s", session.user, session.proc_prefix,
    ext_request_name);

  pr_trace_msg(trace_channel, 7, "received request: EXTENDED %s",
    ext_request_name);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  /* We always handle an EXTENDED vendor-id request from the client; the
   * client is telling us its vendor information; it is not requesting that
   * we send our vendor information.
   */
  if (strncmp(ext_request_name, "vendor-id", 10) == 0) {
    res = fxp_handle_ext_vendor_id(fxp);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }

  if ((fxp_ext_flags & SFTP_FXP_EXT_VERSION_SELECT) &&
      strncmp(ext_request_name, "version-select", 15) == 0) {
    char *version_str;

    version_str = sftp_msg_read_string(fxp->pool, &fxp->payload,
      &fxp->payload_sz);

    res = fxp_handle_ext_version_select(fxp, version_str);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }

  if ((fxp_ext_flags & SFTP_FXP_EXT_CHECK_FILE) &&
      strncmp(ext_request_name, "check-file-name", 16) == 0) {
    char *path, *digest_list;
    off_t offset, len;
    uint32_t blocksz;

    path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
    digest_list = sftp_msg_read_string(fxp->pool, &fxp->payload,
      &fxp->payload_sz);
    offset = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);
    len = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);
    blocksz = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

    res = fxp_handle_ext_check_file(fxp, digest_list, path, offset, len,
      blocksz);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }

  if ((fxp_ext_flags & SFTP_FXP_EXT_CHECK_FILE) &&
      strncmp(ext_request_name, "check-file-handle", 18) == 0) {
    char *handle, *path, *digest_list;
    off_t offset, len;
    uint32_t blocksz;
    struct fxp_handle *fxh;

    handle = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

    fxh = fxp_handle_get(handle);
    if (fxh == NULL ||
        fxh->dirh != NULL) {
      status_code = SSH2_FX_INVALID_HANDLE;

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, fxp_strerror(status_code));

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        fxp_strerror(status_code), NULL);

      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      return fxp_packet_write(resp);
    }

    /* Make sure the file was opened with read permissions; if it was opened
     * write-only, for example, we need to return EACCES.
     */
    if (fxh->fh_flags & O_WRONLY) {
      status_code = SSH2_FX_PERMISSION_DENIED;
   
      pr_trace_msg(trace_channel, 9, "file %s opened write-only, "
        "unable to obtain file checksum (%s)", fxh->fh->fh_path,
        strerror(EACCES));
 
      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, fxp_strerror(status_code));

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        fxp_strerror(status_code), NULL);

      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      return fxp_packet_write(resp);
    }

    path = fxh->fh->fh_path;

    digest_list = sftp_msg_read_string(fxp->pool, &fxp->payload,
      &fxp->payload_sz);
    offset = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);
    len = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);
    blocksz = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

    res = fxp_handle_ext_check_file(fxp, digest_list, path, offset, len,
      blocksz);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }

  if ((fxp_ext_flags & SFTP_FXP_EXT_COPY_FILE) &&
      strncmp(ext_request_name, "copy-file", 10) == 0) {
    char *src, *dst;
    int overwrite;

    src = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
    dst = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
    overwrite = sftp_msg_read_bool(fxp->pool, &fxp->payload, &fxp->payload_sz);

    res = fxp_handle_ext_copy_file(fxp, src, dst, overwrite);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }

  if ((fxp_ext_flags & SFTP_FXP_EXT_FSYNC) &&
      strncmp(ext_request_name, "fsync@openssh.com", 18) == 0) {
    const char *handle;
    struct fxp_handle *fxh;

    handle = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

    fxh = fxp_handle_get(handle);
    if (fxh == NULL) {
      pr_trace_msg(trace_channel, 17,
        "%s: unable to find handle for name '%s': %s", (char *) cmd->argv[0],
        handle, strerror(errno));

      status_code = SSH2_FX_INVALID_HANDLE;

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, fxp_strerror(status_code));

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        fxp_strerror(status_code), NULL);

      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      return fxp_packet_write(resp);
    }

    if (fxh->fh == NULL) {
      errno = EISDIR;

      pr_trace_msg(trace_channel, 17,
        "%s: handle '%s': %s", (char *) cmd->argv[0], handle, strerror(errno));

      status_code = SSH2_FX_INVALID_HANDLE;

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, fxp_strerror(status_code));

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        fxp_strerror(status_code), NULL);

      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      return fxp_packet_write(resp);
    }

    res = fxp_handle_ext_fsync(fxp, fxh);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }

  if ((fxp_ext_flags & SFTP_FXP_EXT_HARDLINK) &&
      strncmp(ext_request_name, "hardlink@openssh.com", 21) == 0) {
    char *src, *dst;

    src = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
    dst = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

    if (fxp_session->client_version >= fxp_utf8_protocol_version) {
      src = sftp_utf8_decode_str(fxp->pool, src);
      dst = sftp_utf8_decode_str(fxp->pool, dst);
    }

    res = fxp_handle_ext_hardlink(fxp, src, dst);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }

  if ((fxp_ext_flags & SFTP_FXP_EXT_POSIX_RENAME) &&
      strncmp(ext_request_name, "posix-rename@openssh.com", 25) == 0) {
    char *src, *dst;

    src = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
    dst = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

    if (fxp_session->client_version >= fxp_utf8_protocol_version) {
      src = sftp_utf8_decode_str(fxp->pool, src);
      dst = sftp_utf8_decode_str(fxp->pool, dst);
    }

    res = fxp_handle_ext_posix_rename(fxp, src, dst);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }

#ifdef HAVE_SYS_STATVFS_H
  if ((fxp_ext_flags & SFTP_FXP_EXT_SPACE_AVAIL) &&
      strncmp(ext_request_name, "space-available", 16) == 0) {
    char *path;

    path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

    res = fxp_handle_ext_space_avail(fxp, path);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }

  if ((fxp_ext_flags & SFTP_FXP_EXT_STATVFS) &&
      strncmp(ext_request_name, "statvfs@openssh.com", 20) == 0) {
    const char *path;

    path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

    res = fxp_handle_ext_statvfs(fxp, path);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }

  if ((fxp_ext_flags & SFTP_FXP_EXT_STATVFS) &&
      strncmp(ext_request_name, "fstatvfs@openssh.com", 21) == 0) {
    const char *handle, *path;
    struct fxp_handle *fxh;

    handle = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

    fxh = fxp_handle_get(handle);
    if (fxh == NULL) {
      pr_trace_msg(trace_channel, 17,
        "%s: unable to find handle for name '%s': %s", (char *) cmd->argv[0],
        handle, strerror(errno));

      status_code = SSH2_FX_INVALID_HANDLE;

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, fxp_strerror(status_code));

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        fxp_strerror(status_code), NULL);

      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      return fxp_packet_write(resp);
    }

    path = fxh->fh ? fxh->fh->fh_path : fxh->dir;

    res = fxp_handle_ext_statvfs(fxp, path);
    if (res == 0) {
      fxp_cmd_dispatch(cmd);

    } else {
      fxp_cmd_dispatch_err(cmd);
    }

    return res;
  }
#endif

#ifdef PR_USE_XATTR
  if (fxp_ext_flags & SFTP_FXP_EXT_XATTR) {
    if (strcmp(ext_request_name, "fgetxattr@proftpd.org") == 0) {
      const char *handle, *name;
      uint32_t valsz;

      handle = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
      name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
      valsz = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

      res = fxp_handle_ext_fgetxattr(fxp, handle, name, valsz);
      if (res == 0) {
        fxp_cmd_dispatch(cmd);

      } else {
        fxp_cmd_dispatch_err(cmd);
      }

      return res;
    }

    if (strcmp(ext_request_name, "flistxattr@proftpd.org") == 0) {
      const char *handle;

      handle = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

      res = fxp_handle_ext_flistxattr(fxp, handle);
      if (res == 0) {
        fxp_cmd_dispatch(cmd);

      } else {
        fxp_cmd_dispatch_err(cmd);
      }

      return res;
    }

    if (strcmp(ext_request_name, "fremovexattr@proftpd.org") == 0) {
      const char *handle, *name;

      handle = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
      name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

      res = fxp_handle_ext_fremovexattr(fxp, handle, name);
      if (res == 0) {
        fxp_cmd_dispatch(cmd);

      } else {
        fxp_cmd_dispatch_err(cmd);
      }

      return res;
    }

    if (strcmp(ext_request_name, "fsetxattr@proftpd.org") == 0) {
      const char *handle, *name;
      void *val;
      uint32_t pflags, valsz;

      handle = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
      name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
      valsz = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);
      val = (void *) sftp_msg_read_data(fxp->pool, &fxp->payload,
        &fxp->payload_sz, valsz);
      pflags = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

      res = fxp_handle_ext_fsetxattr(fxp, handle, name, val, valsz, pflags);
      if (res == 0) {
        fxp_cmd_dispatch(cmd);

      } else {
        fxp_cmd_dispatch_err(cmd);
      }

      return res;
    }

    if (strcmp(ext_request_name, "getxattr@proftpd.org") == 0) {
      const char *path, *name;
      uint32_t valsz;

      path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
      name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
      valsz = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

      res = fxp_handle_ext_getxattr(fxp, path, name, valsz);
      if (res == 0) {
        fxp_cmd_dispatch(cmd);

      } else {
        fxp_cmd_dispatch_err(cmd);
      }

      return res;
    }

    if (strcmp(ext_request_name, "listxattr@proftpd.org") == 0) {
      const char *path;

      path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

      res = fxp_handle_ext_listxattr(fxp, path);
      if (res == 0) {
        fxp_cmd_dispatch(cmd);

      } else {
        fxp_cmd_dispatch_err(cmd);
      }

      return res;
    }

    if (strcmp(ext_request_name, "removexattr@proftpd.org") == 0) {
      const char *path, *name;

      path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
      name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

      res = fxp_handle_ext_removexattr(fxp, path, name);
      if (res == 0) {
        fxp_cmd_dispatch(cmd);

      } else {
        fxp_cmd_dispatch_err(cmd);
      }

      return res;
    }

    if (strcmp(ext_request_name, "setxattr@proftpd.org") == 0) {
      const char *path, *name;
      void *val;
      uint32_t pflags, valsz;

      path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
      name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
      valsz = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);
      val = (void *) sftp_msg_read_data(fxp->pool, &fxp->payload,
        &fxp->payload_sz, valsz);
      pflags = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

      res = fxp_handle_ext_setxattr(fxp, path, name, val, valsz, pflags);
      if (res == 0) {
        fxp_cmd_dispatch(cmd);

      } else {
        fxp_cmd_dispatch_err(cmd);
      }

      return res;
    }
  }
#endif /* PR_USE_XATTR */

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "client requested '%s' extension, rejecting", ext_request_name);
  status_code = SSH2_FX_OP_UNSUPPORTED;

  fxp_cmd_dispatch_err(cmd);

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, fxp_strerror(status_code));

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    fxp_strerror(status_code), NULL);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);
  
  return fxp_packet_write(resp);
}

static int fxp_handle_fsetstat(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *attrs_str, *cmd_name, *name, *path;
  const char *reason;
  uint32_t attr_flags, buflen, bufsz, status_code;
  int have_error = FALSE, res;
  struct stat *attrs;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  cmd_rec *cmd;
  array_header *xattrs = NULL;

  name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

  cmd = fxp_cmd_alloc(fxp->pool, "FSETSTAT", name);
  cmd->cmd_class = CL_WRITE|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "FSETSTAT", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", name, NULL, NULL);

  attrs = fxp_attrs_read(fxp, &fxp->payload, &fxp->payload_sz, &attr_flags,
    &xattrs);
  if (attrs == NULL) {
    fxp_cmd_dispatch_err(cmd);

    /* XXX TODO: Provide a response to the client here! */
    return 0;
  }

  attrs_str = fxp_strattrs(fxp->pool, attrs, &attr_flags);

  pr_proctitle_set("%s - %s: FSETSTAT %s %s", session.user, session.proc_prefix,
    name, attrs_str);

  pr_trace_msg(trace_channel, 7, "received request: FSETSTAT %s %s", name,
    attrs_str);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  fxh = fxp_handle_get(name);
  if (fxh == NULL) {
    pr_trace_msg(trace_channel, 17,
      "%s: unable to find handle for name '%s': %s", (char *) cmd->argv[0],
      name, strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* Add a note containing the file handle for logging (Bug#3707). */
  fxp_set_filehandle_note(cmd, fxh);

  cmd->arg = pstrdup(cmd->pool, (fxh->fh ? fxh->fh->fh_path : fxh->dir));

  if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "FSETSTAT of '%s' blocked by '%s' handler", cmd->arg,
      (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = dir_best_path(fxp->pool, cmd->arg);
  if (path == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "FSETSTAT request denied: unable to access path '%s'", cmd->arg);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  cmd_name = cmd->argv[0];

  pr_cmd_set_name(cmd, "FSETSTAT");
  if (dir_check(fxp->pool, cmd, G_WRITE, path, NULL) > 0) {
    /* Explicitly allowed by <Limit FSETSTAT>. */
    have_error = FALSE;

  } else {
    pr_cmd_set_name(cmd, "SETSTAT");

    if (!dir_check(fxp->pool, cmd, G_WRITE, path, NULL)) {
      have_error = TRUE;
    }
  }

  if (have_error) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "FSETSTAT of '%s' blocked by <Limit %s> configuration", path,
      (char *) cmd->argv[0]);

    pr_cmd_set_name(cmd, cmd_name);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }
  pr_cmd_set_name(cmd, cmd_name);

  attr_flags = fxp_attrs_clear_unsupported(attr_flags);

  /* If the SFTPOption for ignoring the owners for SFTP setstat requests is set,
   * handle it by clearing the SSH2_FX_ATTR_UIDGID and SSH2_FX_ATTR_OWNERGROUP
   * flags.
   */
  if ((sftp_opts & SFTP_OPT_IGNORE_SFTP_SET_OWNERS) &&
      ((attr_flags & SSH2_FX_ATTR_UIDGID) ||
       (attr_flags & SSH2_FX_ATTR_OWNERGROUP))) {
    pr_trace_msg(trace_channel, 7, "SFTPOption 'IgnoreSFTPSetOwners' "
      "configured, ignoring ownership sent by client");
    attr_flags &= ~SSH2_FX_ATTR_UIDGID;
    attr_flags &= ~SSH2_FX_ATTR_OWNERGROUP;
  }

  /* If the SFTPOption for ignoring the xattrs for SFTP setstat requests is set,
   * handle it by clearing the SSH2_FX_ATTR_EXTENDED flag.
   */
  if ((sftp_opts & SFTP_OPT_IGNORE_SFTP_SET_XATTRS) &&
      (attr_flags & SSH2_FX_ATTR_EXTENDED)) {
    pr_trace_msg(trace_channel, 7,
      "SFTPOption 'IgnoreSFTPSetExtendedAttributes' configured, ignoring "
      "xattrs sent by client");
    attr_flags &= ~SSH2_FX_ATTR_EXTENDED;
  }

  /* If the SFTPOption for ignoring the perms for SFTP setstat requests is set,
   * handle it by clearing the SSH2_FX_ATTR_PERMISSIONS flag.
   */
  if ((sftp_opts & SFTP_OPT_IGNORE_SFTP_SET_PERMS) &&
      (attr_flags & SSH2_FX_ATTR_PERMISSIONS)) {
    pr_trace_msg(trace_channel, 7, "SFTPOption 'IgnoreSFTPSetPerms' "
      "configured, ignoring perms sent by client");
    attr_flags &= ~SSH2_FX_ATTR_PERMISSIONS;
  }

  /* If the SFTPOption for ignoring the times for SFTP setstat requests is set,
   * handle it by clearing the time-related SSH2_FX_ATTR flags.
   */
  if (sftp_opts & SFTP_OPT_IGNORE_SFTP_SET_TIMES) {
    if ((attr_flags & SSH2_FX_ATTR_ACCESSTIME) ||
        (attr_flags & SSH2_FX_ATTR_MODIFYTIME)) {
      pr_trace_msg(trace_channel, 7, "SFTPOption 'IgnoreSFTPSetTimes' "
        "configured, ignoring times sent by client");
      attr_flags &= ~SSH2_FX_ATTR_ACCESSTIME;
      attr_flags &= ~SSH2_FX_ATTR_MODIFYTIME;
    }
  }

  if (fxh->fh != NULL) {
    res = fxp_attrs_set(fxh->fh, fxh->fh->fh_path, attrs, attr_flags, xattrs,
      &buf, &buflen, fxp);

  } else {
    res = fxp_attrs_set(NULL, fxh->dir, attrs, attr_flags, xattrs, &buf,
      &buflen, fxp);
  }

  if (res < 0) {
    int xerrno = errno;

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  status_code = fxp_errno2status(0, &reason);

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, reason);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_fstat(struct fxp_packet *fxp) {
  unsigned char *buf;
  char *cmd_name, *name;
  uint32_t attr_flags, buflen;
  struct stat st;
  struct fxp_buffer *fxb;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  cmd_rec *cmd;
  const char *fake_user = NULL, *fake_group = NULL;

  name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

  cmd = fxp_cmd_alloc(fxp->pool, "FSTAT", name);
  cmd->cmd_class = CL_READ|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "FSTAT", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", name, NULL, NULL);

  pr_proctitle_set("%s - %s: FSTAT %s", session.user, session.proc_prefix,
    name);

  if (fxp_session->client_version > 3) {
    attr_flags = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

    pr_trace_msg(trace_channel, 7, "received request: FSTAT %s %s", name,
      fxp_strattrflags(fxp->pool, attr_flags));

  } else {
    pr_trace_msg(trace_channel, 7, "received request: FSTAT %s", name);
    attr_flags = SSH2_FX_ATTR_SIZE|SSH2_FX_ATTR_UIDGID|SSH2_FX_ATTR_PERMISSIONS|
      SSH2_FX_ATTR_ACMODTIME;
#ifdef PR_USE_XATTR
    if (!(fxp_fsio_opts & PR_FSIO_OPT_IGNORE_XATTR)) {
      attr_flags |= SSH2_FX_ATTR_EXTENDED;
    }
#endif /* PR_USE_XATTR */
  }

  fxb = pcalloc(fxp->pool, sizeof(struct fxp_buffer));
  fxb->bufsz = buflen = FXP_RESPONSE_NAME_DEFAULT_SZ;
  fxb->ptr = buf = palloc(fxp->pool, fxb->bufsz);

  fxh = fxp_handle_get(name);
  if (fxh == NULL) {
    uint32_t status_code;

    pr_trace_msg(trace_channel, 17,
      "%s: unable to find handle for name '%s': %s", (char *) cmd->argv[0],
      name, strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->fh == NULL) {
    uint32_t status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  /* Add a note containing the file handle for logging (Bug#3707). */
  fxp_set_filehandle_note(cmd, fxh);

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "FSTAT");

  if (!dir_check(fxp->pool, cmd, G_NONE, fxh->fh->fh_path, NULL)) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    pr_cmd_set_name(cmd, cmd_name);

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "FSTAT of '%s' blocked by <Limit> configuration", fxh->fh->fh_path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }
  pr_cmd_set_name(cmd, cmd_name);

  if (pr_fsio_fstat(fxh->fh, &st) < 0) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error checking '%s' for FSTAT: %s", fxh->fh->fh_path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8, "sending response: ATTRS %s",
    fxp_strattrs(fxp->pool, &st, NULL));

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_ATTRS);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);

  fake_user = get_param_ptr(get_dir_ctxt(fxp->pool, fxh->fh->fh_path),
    "DirFakeUser", FALSE);
  if (fake_user != NULL &&
      strncmp(fake_user, "~", 2) == 0) {
    fake_user = session.user;
  }

  fake_group = get_param_ptr(get_dir_ctxt(fxp->pool, fxh->fh->fh_path),
    "DirFakeGroup", FALSE);
  if (fake_group != NULL &&
      strncmp(fake_group, "~", 2) == 0) {
    fake_group = session.group;
  }

  fxb->buf = buf;
  fxb->buflen = buflen;

  attr_flags = fxp_attrs_clear_unsupported(attr_flags);
  if (fxp_session->client_version > 3 &&
      sftp_opts & SFTP_OPT_INCLUDE_SFTP_TIMES) {
    pr_trace_msg(trace_channel, 17,
      "SFTPOption IncludeSFTPTimes in effect; assuring presence of "
      "ACCESSTIME/MODIFYTIME attributes");
    attr_flags |= SSH2_FX_ATTR_ACCESSTIME;
    attr_flags |= SSH2_FX_ATTR_MODIFYTIME;
  }

  fxp_attrs_write(fxp->pool, fxb, fxh->fh->fh_path, &st, attr_flags, fake_user,
    fake_group);

  /* fxp_attrs_write will have changed the buf/buflen values in the buffer. */
  buf = fxb->buf;
  buflen = fxb->buflen;

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = fxb->ptr;
  resp->payload_sz = (fxb->bufsz - buflen);
  
  return fxp_packet_write(resp);
}

static int fxp_handle_init(struct fxp_packet *fxp) {
  char version_str[16];
  unsigned char *buf, *ptr;
  uint32_t buflen, bufsz;
  struct fxp_packet *resp;
  cmd_rec *cmd;
  config_rec *c;

  fxp_session->client_version = sftp_msg_read_int(fxp->pool, &fxp->payload,
    &fxp->payload_sz);

  memset(version_str, '\0', sizeof(version_str));
  pr_snprintf(version_str, sizeof(version_str)-1, "%lu",
    (unsigned long) fxp_session->client_version);

  cmd = fxp_cmd_alloc(fxp->pool, "INIT", version_str);
  cmd->cmd_class = CL_MISC|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "INIT", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", version_str, NULL, NULL);

  pr_proctitle_set("%s - %s: INIT %s", session.user, session.proc_prefix,
    version_str);

  pr_trace_msg(trace_channel, 7, "received request: INIT %lu",
    (unsigned long) fxp_session->client_version);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_VERSION);

  if (fxp_session->client_version > fxp_max_client_version) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested SFTP protocol version %lu, which exceeds "
      "SFTPClientMatch max SFTP protocol version %u, using protocol version %u",
      (unsigned long) fxp_session->client_version, fxp_max_client_version,
      fxp_max_client_version);
    fxp_session->client_version = fxp_max_client_version;
  }

  if (fxp_session->client_version < fxp_min_client_version) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested SFTP protocol version %lu, which is less than "
      "SFTPClientMatch min SFTP protocol version %u, using protocol version %u",
      (unsigned long) fxp_session->client_version, fxp_min_client_version,
      fxp_min_client_version);
    fxp_session->client_version = fxp_min_client_version;
  }

#ifndef PR_USE_NLS
  /* If NLS supported was enabled in the proftpd build, then we can support
   * UTF8, and thus every other version of SFTP.  Otherwise, we can only
   * support up to version 3.
   */
  if (fxp_session->client_version > 3) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested SFTP protocol version %lu, but we can only support "
      "protocol version 3 due to lack of UTF8 support (requires --enable-nls)",
      (unsigned long) fxp_session->client_version);
    fxp_session->client_version = 3;
  }
#endif

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "using SFTP protocol version %lu for this session (channel ID %lu)",
    (unsigned long) fxp_session->client_version,
    (unsigned long) fxp->channel_id);

  pr_trace_msg(trace_channel, 8, "sending response: VERSION %lu",
    (unsigned long) fxp_session->client_version);

  sftp_msg_write_int(&buf, &buflen, fxp_session->client_version);

  if (fxp_ext_flags & SFTP_FXP_EXT_VENDOR_ID) {
    fxp_version_add_vendor_id_ext(fxp->pool, &buf, &buflen);
  }

  fxp_version_add_version_ext(fxp->pool, &buf, &buflen);

  if (fxp_session->client_version >= 4) {
    fxp_version_add_newline_ext(fxp->pool, &buf, &buflen);
  }

  if (fxp_session->client_version == 5) {
    fxp_version_add_supported_ext(fxp->pool, &buf, &buflen);
  }

  if (fxp_session->client_version >= 6) {
    fxp_version_add_supported2_ext(fxp->pool, &buf, &buflen);
  }

  fxp_version_add_openssh_exts(fxp->pool, &buf, &buflen);

  /* Look up the FSOptions here, for use later (Issue #593).  We do not need
   * set these for the FSIO API; that is already done by mod_core.  Instead,
   * we look them up for ourselves, for our own consumption/use.
   */
  c = find_config(main_server->conf, CONF_PARAM, "FSOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    fxp_fsio_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "FSOptions", FALSE);
  }

  pr_event_generate("mod_sftp.sftp.protocol-version",
    &(fxp_session->client_version));

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_link(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *args, *cmd_name, *link_path, *target_path;
  const char *reason;
  char is_symlink;
  int have_error = FALSE, res;
  uint32_t buflen, bufsz, status_code;
  struct fxp_packet *resp;
  cmd_rec *cmd;

  link_path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    link_path = sftp_utf8_decode_str(fxp->pool, link_path);
  }

  target_path = sftp_msg_read_string(fxp->pool, &fxp->payload,
    &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    target_path = sftp_utf8_decode_str(fxp->pool, target_path);
  }

  args = pstrcat(fxp->pool, link_path, " ", target_path, NULL);

  cmd = fxp_cmd_alloc(fxp->pool, "LINK", args);
  cmd->cmd_class = CL_WRITE|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "LINK", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", args, NULL, NULL);

  is_symlink = sftp_msg_read_byte(fxp->pool, &fxp->payload, &fxp->payload_sz);

  pr_proctitle_set("%s - %s: LINK %s %s %s", session.user, session.proc_prefix,
    link_path, target_path, is_symlink ? "true" : "false");

  pr_trace_msg(trace_channel, 7, "received request: LINK %s %s %s", link_path,
    target_path, is_symlink ? "true" : "false");

  if (strlen(link_path) == 0) {
    /* Use the default directory if the path is empty. */
    link_path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty link path given in LINK request, using '%s'", link_path);
  }

  if (strlen(target_path) == 0) {
    /* Use the default directory if the path is empty. */
    target_path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty target path given in LINK request, using '%s'", target_path);
  }

  /* Make sure we use the full paths. */
  link_path = dir_canonical_vpath(fxp->pool, link_path);
  target_path = dir_canonical_vpath(fxp->pool, target_path);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "LINK");

  if (!dir_check(fxp->pool, cmd, G_READ, target_path, NULL)) {
    have_error = TRUE;
  }

  if (!have_error) {
    if (!dir_check(fxp->pool, cmd, G_WRITE, link_path, NULL)) {
      have_error = TRUE;
    }
  }

  if (is_symlink) {
    if (!have_error) {
      pr_cmd_set_name(cmd, "SYMLINK");

      if (!dir_check(fxp->pool, cmd, G_READ, target_path, NULL)) {
        have_error = TRUE;
      }

      if (!have_error) {
        if (!dir_check(fxp->pool, cmd, G_WRITE, link_path, NULL)) {
          have_error = TRUE;
        }
      }
    }
  }

  if (have_error) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "LINK of '%s' to '%s' blocked by <Limit %s> configuration",
      target_path, link_path, (char *) cmd->argv[0]);

    pr_cmd_set_name(cmd, cmd_name);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_cmd_set_name(cmd, cmd_name);

  if (is_symlink) {
    res = pr_fsio_symlink(target_path, link_path);

  } else {
    res = pr_fsio_link(target_path, link_path);
  }

  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error %s '%s' to '%s': %s", is_symlink ? "symlinking" : "linking",
      target_path, link_path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_cmd_dispatch_err(cmd);

  } else {
    errno = 0;
    status_code = fxp_errno2status(0, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_cmd_dispatch(cmd);
  }

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_lock(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *name;
  const char *lock_type_str = NULL;
  uint32_t buflen, bufsz, lock_flags, status_code;
  uint64_t offset, lock_len;
  struct flock lock;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  cmd_rec *cmd;
  
  name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  offset = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);
  lock_len = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);
  lock_flags = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

  cmd = fxp_cmd_alloc(fxp->pool, "LOCK", name);
  cmd->cmd_class = CL_WRITE|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "LOCK", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", name, NULL, NULL);

  pr_proctitle_set("%s - %s: LOCK %s", session.user, session.proc_prefix, name);

  pr_trace_msg(trace_channel, 7,
    "received request: LOCK %s %" PR_LU " %" PR_LU " %lu",
    name, (pr_off_t) offset, (pr_off_t) lock_len, (unsigned long) lock_flags);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  fxh = fxp_handle_get(name);
  if (fxh == NULL) {
    pr_trace_msg(trace_channel, 17,
      "%s: unable to find handle for name '%s': %s", (char *) cmd->argv[0],
      name, strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->fh == NULL) {
    /* We do not support locking of directory handles, only files. */
    status_code = SSH2_FX_OP_UNSUPPORTED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested unsupported LOCK of a directory, rejecting");

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  if (!dir_check(fxp->pool, cmd, G_WRITE, fxh->fh->fh_path, NULL)) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "LOCK of '%s' blocked by <Limit> configuration", fxh->fh->fh_path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", fxh->fh->fh_path, NULL, NULL);

  if (lock_flags & SSH2_FXL_DELETE) {
    /* The UNLOCK command is used for removing locks, not LOCK. */
    status_code = SSH2_FX_OP_UNSUPPORTED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested lock removal using LOCK, rejecting");

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);
  
    return fxp_packet_write(resp);

  } else {
    if ((lock_flags & SSH2_FXL_WRITE) &&
        (lock_flags & SSH2_FXL_READ)) {
      /* We do not support simultaneous read and write locking. */
      status_code = SSH2_FX_OP_UNSUPPORTED;

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client requested unsupported simultaneous read/write LOCK, "
        "rejecting");

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, fxp_strerror(status_code));

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        fxp_strerror(status_code), NULL);

      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);
  
      return fxp_packet_write(resp);
    }

    if (lock_flags & SSH2_FXL_READ) {
      lock.l_type = F_RDLCK;
      lock_type_str = "read";
    }

    if (lock_flags & SSH2_FXL_WRITE) {
      lock.l_type = F_WRLCK;
      lock_type_str = "write";
    }
  }

  lock.l_whence = SEEK_SET;
  lock.l_start = offset;
  lock.l_len = lock_len;

  if (lock_len > 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested %s locking of '%s' from %" PR_LU " for %" PR_LU
      " bytes", lock_type_str, fxh->fh->fh_path, (pr_off_t) offset,
      (pr_off_t) lock_len);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested %s locking of '%s' from %" PR_LU " to end-of-file",
      lock_type_str, fxh->fh->fh_path, (pr_off_t) offset);
  }

  pr_trace_msg("lock", 9, "attempting to %s lock file '%s'", lock_type_str,
    fxh->fh->fh_path);

  while (fcntl(fxh->fh->fh_fd, F_SETLKW, &lock) < 0) {
    int xerrno;
    const char *reason;

    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    xerrno = errno;
    pr_trace_msg("lock", 3, "%s-lock of '%s' failed: %s", lock_type_str,
      fxh->fh->fh_path, strerror(errno)); 

    if (errno == EACCES) { 
      /* Get the PID of the process blocking this lock. */
      if (fcntl(fxh->fh->fh_fd, F_GETLK, &lock) == 0) {
        pr_trace_msg("lock", 3, "process ID %lu has blocking %s lock on '%s'",
          (unsigned long) lock.l_pid, lock.l_type == F_RDLCK ? "read" : "write",
          fxh->fh->fh_path);
      }

      status_code = SSH2_FX_LOCK_CONFLICT;
      reason = fxp_strerror(status_code);

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, reason);

    } else {
      status_code = fxp_errno2status(xerrno, &reason);

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
        "('%s' [%d])", (unsigned long) status_code, reason,
        xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);
    }

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg("lock", 9, "%s lock of file '%s' successful", lock_type_str,
    fxh->fh->fh_path);

  status_code = SSH2_FX_OK;

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, fxp_strerror(status_code));

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    fxp_strerror(status_code), NULL);

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_lstat(struct fxp_packet *fxp) {
  unsigned char *buf;
  char *cmd_name, *path;
  uint32_t attr_flags, buflen;
  struct stat st;
  struct fxp_buffer *fxb;
  struct fxp_packet *resp;
  cmd_rec *cmd;
  const char *fake_user = NULL, *fake_group = NULL;

  path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    path = sftp_utf8_decode_str(fxp->pool, path);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "LSTAT", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", path, NULL, NULL);

  pr_proctitle_set("%s - %s: LSTAT %s", session.user, session.proc_prefix,
    path);

  if (fxp_session->client_version > 3) {
    attr_flags = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

    pr_trace_msg(trace_channel, 7, "received request: LSTAT %s %s", path,
      fxp_strattrflags(fxp->pool, attr_flags));

  } else {
    pr_trace_msg(trace_channel, 7, "received request: LSTAT %s", path);
    attr_flags = SSH2_FX_ATTR_SIZE|SSH2_FX_ATTR_UIDGID|SSH2_FX_ATTR_PERMISSIONS|
      SSH2_FX_ATTR_ACMODTIME;
#ifdef PR_USE_XATTR
    if (!(fxp_fsio_opts & PR_FSIO_OPT_IGNORE_XATTR)) {
      attr_flags |= SSH2_FX_ATTR_EXTENDED;
    }
#endif /* PR_USE_XATTR */
  }

  if (strlen(path) == 0) {
    /* Use the default directory if the path is empty. */
    path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty path given in LSTAT request, using '%s'", path);
  }

  cmd = fxp_cmd_alloc(fxp->pool, "LSTAT", path);
  cmd->cmd_class = CL_READ|CL_SFTP;

  fxb = pcalloc(fxp->pool, sizeof(struct fxp_buffer));
  fxb->bufsz = buflen = FXP_RESPONSE_NAME_DEFAULT_SZ;
  fxb->ptr = buf = palloc(fxp->pool, fxb->bufsz);

  if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "LSTAT of '%s' blocked by '%s' handler", path, (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = dir_best_path(fxp->pool, cmd->arg);
  if (path == NULL) {
    int xerrno = EACCES;
    const char *reason;
    uint32_t status_code;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "LSTAT request denied: unable to access path '%s'", cmd->arg);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
       xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "LSTAT");

  if (!dir_check(fxp->pool, cmd, G_NONE, path, NULL)) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    pr_cmd_set_name(cmd, cmd_name);

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "LSTAT of '%s' blocked by <Limit> configuration", path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }
  pr_cmd_set_name(cmd, cmd_name);

  pr_fs_clear_cache2(path);
  if (pr_fsio_lstat(path, &st) < 0) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error checking '%s' for LSTAT: %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8, "sending response: ATTRS %s",
    fxp_strattrs(fxp->pool, &st, NULL));

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_ATTRS);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);

  fake_user = get_param_ptr(get_dir_ctxt(fxp->pool, path), "DirFakeUser",
    FALSE);
  if (fake_user != NULL &&
      strncmp(fake_user, "~", 2) == 0) {
    fake_user = session.user;
  }

  fake_group = get_param_ptr(get_dir_ctxt(fxp->pool, path), "DirFakeGroup",
    FALSE);
  if (fake_group != NULL &&
      strncmp(fake_group, "~", 2) == 0) {
    fake_group = session.group;
  }

  fxb->buf = buf;
  fxb->buflen = buflen;

  attr_flags = fxp_attrs_clear_unsupported(attr_flags);
  if (fxp_session->client_version > 3 &&
      sftp_opts & SFTP_OPT_INCLUDE_SFTP_TIMES) {
    pr_trace_msg(trace_channel, 17,
      "SFTPOption IncludeSFTPTimes in effect; assuring presence of "
      "ACCESSTIME/MODIFYTIME attributes");
    attr_flags |= SSH2_FX_ATTR_ACCESSTIME;
    attr_flags |= SSH2_FX_ATTR_MODIFYTIME;
  }

  fxp_attrs_write(fxp->pool, fxb, path, &st, attr_flags, fake_user, fake_group);

  /* fxp_attrs_write will have changed the buf/buflen fields in the buffer. */
  buf = fxb->buf;
  buflen = fxb->buflen;

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = fxb->ptr;
  resp->payload_sz = (fxb->bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_mkdir(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *attrs_str, *cmd_name, *path;
  struct stat *attrs, st;
  int have_error = FALSE, res = 0;
  mode_t dir_mode;
  uint32_t attr_flags, buflen, bufsz, status_code;
  struct fxp_packet *resp;
  cmd_rec *cmd, *cmd2;
  array_header *xattrs = NULL;

  path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    path = sftp_utf8_decode_str(fxp->pool, path);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "MKDIR", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", path, NULL, NULL);

  attrs = fxp_attrs_read(fxp, &fxp->payload, &fxp->payload_sz, &attr_flags,
    &xattrs);
  if (attrs == NULL) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "MKDIR request missing required attributes, ignoring");
    return 0;
  }

  /* If the SFTPOption for ignoring perms for SFTP uploads is set, handle
   * it by clearing the SSH2_FX_ATTR_PERMISSIONS flag.
   */
  if ((sftp_opts & SFTP_OPT_IGNORE_SFTP_UPLOAD_PERMS) &&
      (attr_flags & SSH2_FX_ATTR_PERMISSIONS)) {
    pr_trace_msg(trace_channel, 7, "SFTPOption 'IgnoreSFTPUploadPerms' "
      "configured, ignoring perms sent by client");
    attr_flags &= ~SSH2_FX_ATTR_PERMISSIONS;
  }

  /* If the SFTPOption for ignoring xattrs for SFTP uploads is set, handle it
   * by clearing the SSH2_FX_ATTR_EXTENDED flag.
   */
  if ((sftp_opts & SFTP_OPT_IGNORE_SFTP_UPLOAD_XATTRS) &&
      (attr_flags & SSH2_FX_ATTR_EXTENDED)) {
    pr_trace_msg(trace_channel, 7,
      "SFTPOption 'IgnoreSFTPUploadExtendedAttributes' configured, "
      "ignoring xattrs sent by client");
    attr_flags &= ~SSH2_FX_ATTR_EXTENDED;
  }

  attrs_str = fxp_strattrs(fxp->pool, attrs, &attr_flags);

  pr_proctitle_set("%s - %s: MKDIR %s %s", session.user, session.proc_prefix,
    path, attrs_str);

  pr_trace_msg(trace_channel, 7, "received request: MKDIR %s %s", path,
    attrs_str);

  if (strlen(path) == 0) {
    /* Use the default directory if the path is empty. */
    path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty path given in MKDIR request, using '%s'", path);
  }

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  cmd = fxp_cmd_alloc(fxp->pool, "MKDIR", path);
  cmd->cmd_class = CL_WRITE|CL_SFTP;

  if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "MKDIR of '%s' blocked by '%s' handler", path, (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  path = cmd->arg;

  cmd2 = fxp_cmd_alloc(fxp->pool, C_MKD, path);
  if (pr_cmd_dispatch_phase(cmd2, PRE_CMD, 0) == -1) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "MKDIR of '%s' blocked by '%s' handler", path, (char *) cmd2->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = cmd2->arg;

  path = dir_canonical_path(fxp->pool, path);
  if (path == NULL) {
    status_code = fxp_errno2status(EINVAL, NULL);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, C_XMKD);

  if (!dir_check_canon(fxp->pool, cmd, G_WRITE, path, NULL)) {
    have_error = TRUE;
  }

  if (have_error) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "MKDIR of '%s' blocked by <Limit %s> configuration", path,
      (char *) cmd->argv[0]);

    pr_cmd_set_name(cmd, cmd_name);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_cmd_set_name(cmd, cmd_name);

  if (fxp_path_pass_regex_filters(fxp->pool, "MKDIR", path) < 0) {
    int xerrno = errno;

    status_code = fxp_errno2status(xerrno, NULL);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  dir_mode = (attr_flags & SSH2_FX_ATTR_PERMISSIONS) ? attrs->st_mode : 0777;

  (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
    "creating directory '%s' with mode 0%o", path, (unsigned int) dir_mode);

  /* Check if the path already exists, to avoid unnecessary work. */
  pr_fs_clear_cache2(path);
  if (pr_fsio_lstat(path, &st) == 0) {
    const char *reason;
    int xerrno = EEXIST;

    (void) pr_trace_msg("fileperms", 1, "MKDIR, user '%s' (UID %s, GID %s): "
      "error making directory '%s': %s", session.user,
      pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
      path, strerror(xerrno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "MKDIR of '%s' failed: %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  res = pr_fsio_smkdir(fxp->pool, path, dir_mode, (uid_t) -1, (gid_t) -1);
  if (res < 0) {
    const char *reason;
    int xerrno = errno;

    (void) pr_trace_msg("fileperms", 1, "MKDIR, user '%s' (UID %s, GID %s): "
      "error making directory '%s': %s", session.user,
      pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
      path, strerror(xerrno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "MKDIR of '%s' failed: %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* Handle any possible UserOwner/GroupOwner directives for created
   * directories.
   */
  if (sftp_misc_chown_path(fxp->pool, path) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error changing ownership on path '%s': %s", path, strerror(errno));
  }

  status_code = SSH2_FX_OK;

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, fxp_strerror(status_code));

  fxp_cmd_dispatch(cmd2);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    fxp_strerror(status_code), NULL);

  pr_response_add(R_257, "\"%s\" - Directory successfully created",
    quote_dir(cmd->tmp_pool, path));
  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_open(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  const char *hiddenstore_path = NULL;
  char *path, *orig_path;
  uint32_t attr_flags, buflen, bufsz, desired_access = 0, flags;
  int file_existed = FALSE, open_flags, res, timeout_stalled;
  pr_fh_t *fh;
  struct stat *attrs, st;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  cmd_rec *cmd, *cmd2 = NULL;
  array_header *xattrs = NULL;

  path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    path = sftp_utf8_decode_str(fxp->pool, path);
  }

  orig_path = path;
  cmd = fxp_cmd_alloc(fxp->pool, "OPEN", path);

  /* Set the command class to MISC for now; we'll change it later to
   * READ or WRITE once we know which it is.
   */
  cmd->cmd_class = CL_MISC|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "OPEN", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", path, NULL, NULL);

  pr_proctitle_set("%s - %s: OPEN %s", session.user, session.proc_prefix, path);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  if (fxp_session->client_version > 4) {
    desired_access = sftp_msg_read_int(fxp->pool, &fxp->payload,
      &fxp->payload_sz);

    /* Check for unsupported flags. */
    if ((desired_access & SSH2_FXF_WANT_READ_NAMED_ATTRS) ||
        (desired_access & SSH2_FXF_WANT_READ_ACL) ||
        (desired_access & SSH2_FXF_WANT_WRITE_NAMED_ATTRS) ||
        (desired_access & SSH2_FXF_WANT_WRITE_ACL) ||
        (desired_access & SSH2_FXF_WANT_WRITE_OWNER)) {
      uint32_t status_code;
      const char *unsupported_str = "";

      if (desired_access & SSH2_FXF_WANT_READ_NAMED_ATTRS) {
        unsupported_str = pstrcat(fxp->pool, unsupported_str,
          *unsupported_str ? "|" : "", "WANT_READ_NAMED_ATTRS", NULL);
      }

      if (desired_access & SSH2_FXF_WANT_READ_ACL) {
        unsupported_str = pstrcat(fxp->pool, unsupported_str,
          *unsupported_str ? "|" : "", "WANT_READ_ACL", NULL);
      }

      if (desired_access & SSH2_FXF_WANT_WRITE_NAMED_ATTRS) {
        unsupported_str = pstrcat(fxp->pool, unsupported_str,
          *unsupported_str ? "|" : "", "WANT_WRITE_NAMED_ATTRS", NULL);
      }

      if (desired_access & SSH2_FXF_WANT_WRITE_ACL) {
        unsupported_str = pstrcat(fxp->pool, unsupported_str,
          *unsupported_str ? "|" : "", "WANT_WRITE_ACL", NULL);
      }

      if (desired_access & SSH2_FXF_WANT_WRITE_OWNER) {
        unsupported_str = pstrcat(fxp->pool, unsupported_str,
          *unsupported_str ? "|" : "", "WANT_WRITE_OWNER", NULL);
      }

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client requested unsupported access '%s' in OPEN command, rejecting",
        unsupported_str);

      status_code = SSH2_FX_OP_UNSUPPORTED;

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, fxp_strerror(status_code));

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        fxp_strerror(status_code), NULL);

      fxp_cmd_note_file_status(cmd, "failed");
      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      return fxp_packet_write(resp);
    }
  }

  flags = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

  /* Check for any unsupported flags. */
  if (fxp_session->client_version > 4) {
    /* XXX If O_SHLOCK and O_EXLOCK are defined, as they are on OSX, the
     * ACCESS_READ_LOCK and ACCESS_WRITE_LOCK flags should be supported.
     *
     * Note that IF we support these LOCK flags, we will need to report
     * this support in the VERSION response as well.
     */

    if ((flags & SSH2_FXF_ACCESS_READ_LOCK) ||
        (flags & SSH2_FXF_ACCESS_WRITE_LOCK) ||
        (flags & SSH2_FXF_ACCESS_DELETE_LOCK)) {
      uint32_t status_code;
      const char *unsupported_str = "";

      if (flags & SSH2_FXF_ACCESS_READ_LOCK) {
        unsupported_str = pstrcat(fxp->pool, unsupported_str,
          *unsupported_str ? "|" : "", "ACCESS_READ_LOCK", NULL);
      }

      if (flags & SSH2_FXF_ACCESS_WRITE_LOCK) {
        unsupported_str = pstrcat(fxp->pool, unsupported_str,
          *unsupported_str ? "|" : "", "ACCESS_WRITE_LOCK", NULL);
      }

      if (flags & SSH2_FXF_ACCESS_DELETE_LOCK) {
        unsupported_str = pstrcat(fxp->pool, unsupported_str,
          *unsupported_str ? "|" : "", "ACCESS_DELETE_LOCK", NULL);
      }

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client requested unsupported flag '%s' in OPEN command, rejecting",
        unsupported_str);

      status_code = SSH2_FX_OP_UNSUPPORTED;

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, fxp_strerror(status_code));

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        fxp_strerror(status_code), NULL);

      fxp_cmd_note_file_status(cmd, "failed");
      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      return fxp_packet_write(resp);
    }

    /* Make sure the requested path exists. */
    pr_fs_clear_cache2(path);
    if ((flags & SSH2_FXF_OPEN_EXISTING) &&
        !exists2(fxp->pool, path)) {
      uint32_t status_code;

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "client requested OPEN_EXISTING flag in OPEN command and '%s' does "
        "not exist", path);

      status_code = SSH2_FX_NO_SUCH_FILE;

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, fxp_strerror(status_code));

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        fxp_strerror(status_code), NULL);

      fxp_cmd_note_file_status(cmd, "failed");
      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      return fxp_packet_write(resp);
    }
  }

  if (fxp_session->client_version < 5) {
    fxp_trace_v3_open_flags(fxp->pool, flags);
    open_flags = fxp_get_v3_open_flags(flags);

  } else {
    fxp_trace_v5_open_flags(fxp->pool, desired_access, flags);
    open_flags = fxp_get_v5_open_flags(desired_access, flags);
  }

  attrs = fxp_attrs_read(fxp, &fxp->payload, &fxp->payload_sz, &attr_flags,
    &xattrs);
  if (attrs == NULL) {
    fxp_cmd_note_file_status(cmd, "failed");
    fxp_cmd_dispatch_err(cmd);

    /* XXX TODO: Provide a response to the client here */
    return 0;
  }

  pr_trace_msg(trace_channel, 7, "received request: OPEN %s %s (%s)",
    path, fxp_strattrs(fxp->pool, attrs, &attr_flags),
    fxp_stroflags(fxp->pool, open_flags));

  if (open_flags & O_APPEND) {
    cmd->cmd_class &= ~CL_MISC;
    cmd->cmd_class |= CL_WRITE;
    cmd2 = fxp_cmd_alloc(fxp->pool, C_APPE, path);
    cmd2->cmd_id = pr_cmd_get_id(C_APPE);
    session.curr_cmd = C_APPE;

    if (pr_table_add(cmd2->notes, "mod_xfer.store-path",
        pstrdup(fxp->pool, path), 0) < 0) {
      if (errno != EEXIST) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error adding 'mod_xfer.store-path' note: %s", strerror(errno));
      }
    }

  } else if ((open_flags & O_WRONLY) ||
             (open_flags & O_RDWR)) {
    cmd2 = fxp_cmd_alloc(fxp->pool, C_STOR, path);
    cmd2->cmd_id = pr_cmd_get_id(C_STOR);

    if (open_flags & O_WRONLY) {
      cmd->cmd_class &= ~CL_MISC;
      cmd->cmd_class |= CL_WRITE;

    } else if (open_flags & O_RDWR) {
      cmd->cmd_class &= ~CL_MISC;
      cmd->cmd_class |= (CL_READ|CL_WRITE);
    }

    session.curr_cmd = C_STOR;

    if (pr_table_add(cmd2->notes, "mod_xfer.store-path",
        pstrdup(fxp->pool, path), 0) < 0) {
      if (errno != EEXIST) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error adding 'mod_xfer.store-path' note: %s", strerror(errno));
      }
    }

  } else if (open_flags == O_RDONLY) {
    cmd->cmd_class &= ~CL_MISC;
    cmd->cmd_class |= CL_READ;
    cmd2 = fxp_cmd_alloc(fxp->pool, C_RETR, path);
    cmd2->cmd_id = pr_cmd_get_id(C_RETR);
    session.curr_cmd = C_RETR;

    /* We ignore any perms sent by the client for read-only requests.
     *
     * This happens because we explicitly call chown(2)/chmod(2) after
     * open(2) in order to handle UserOwner/GroupOwner directive.  But this
     * breaks the semantics of open(2), which does not change the mode of
     * an existing file if the flags are O_RDONLY.
     */
    if (attr_flags & SSH2_FX_ATTR_PERMISSIONS) {
      pr_trace_msg(trace_channel, 15,
        "read-only OPEN request, ignoring perms sent by client");
      attr_flags &= ~SSH2_FX_ATTR_PERMISSIONS;
    }

    if (pr_table_add(cmd2->notes, "mod_xfer.retr-path",
        pstrdup(fxp->pool, path), 0) < 0) {
      if (errno != EEXIST) {
        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error adding 'mod_xfer.retr-path' note: %s", strerror(errno));
      }
    }
  }

  if (cmd2) {
    if (pr_cmd_dispatch_phase(cmd2, PRE_CMD, 0) < 0) {
      int xerrno = errno;
      const char *reason;
      uint32_t status_code;

      /* One of the PRE_CMD phase handlers rejected the command. */

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "OPEN command for '%s' blocked by '%s' handler", path,
        (char *) cmd2->argv[0]);

      /* Hopefully the command handlers set an appropriate errno value.  If
       * they didn't, however, we need to be prepared with a fallback.
       */
      if (xerrno != ENOENT &&
          xerrno != EPERM &&
#if defined(EDQUOT)
          xerrno != EDQUOT &&
#endif /* EDQUOT */
#if defined(EFBIG)
          xerrno != EFBIG &&
#endif /* EFBIG */
#if defined(ENOSPC)
          xerrno != ENOSPC &&
#endif /* ENOSPC */
          xerrno != EINVAL) {
        xerrno = EACCES;
      }

      status_code = fxp_errno2status(xerrno, &reason);

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
        "('%s' [%d])", (unsigned long) status_code, reason, strerror(errno),
        xerrno);

      pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
      fxp_cmd_note_file_status(cmd2, "failed");
      fxp_cmd_dispatch_err(cmd2);

      fxp_cmd_note_file_status(cmd, "failed");
      fxp_cmd_dispatch_err(cmd);

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        reason, NULL);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);

      return fxp_packet_write(resp);
    }

    path = cmd2->arg;

    if (session.xfer.xfer_type == STOR_HIDDEN) {
      const void *nfs;

      hiddenstore_path = pr_table_get(cmd2->notes,
        "mod_xfer.store-hidden-path", NULL);

      nfs = pr_table_get(cmd2->notes, "mod_xfer.store-hidden-nfs", NULL);
      if (nfs == NULL) {
        open_flags |= O_EXCL;
      }

    } else {
      pr_fs_clear_cache2(path);
      if (pr_fsio_lstat(path, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
          char link_path[PR_TUNABLE_PATH_MAX];
          int len;

          memset(link_path, '\0', sizeof(link_path));
          len = dir_readlink(fxp->pool, path, link_path, sizeof(link_path)-1,
            PR_DIR_READLINK_FL_HANDLE_REL_PATH);
          if (len > 0) {
            link_path[len] = '\0';
            path = pstrdup(fxp->pool, link_path);
          } else {
            path = dir_best_path(fxp->pool, path);
          }

        } else {
          path = dir_best_path(fxp->pool, path);
        }

      } else {
        path = dir_best_path(fxp->pool, path);
      }
    }

    if (hiddenstore_path != NULL) {
      pr_fs_clear_cache2(hiddenstore_path);
    }

    file_existed = exists2(fxp->pool,
      hiddenstore_path ? hiddenstore_path : path);

    if (file_existed &&
        (pr_cmd_cmp(cmd2, PR_CMD_STOR_ID) == 0 ||
         pr_cmd_cmp(cmd2, PR_CMD_APPE_ID) == 0)) {

      /* Clear any existing key in the notes. */
      (void) pr_table_remove(cmd->notes, "mod_xfer.file-modified", NULL);

      if (pr_table_add(cmd->notes, "mod_xfer.file-modified",
          pstrdup(cmd->pool, "true"), 0) < 0) {
        if (errno != EEXIST) {
          pr_log_pri(PR_LOG_NOTICE,
            "notice: error adding 'mod_xfer.file-modified' note: %s",
            strerror(errno));
        }
      }

      /* Clear any existing key in the notes. */
      (void) pr_table_remove(cmd2->notes, "mod_xfer.file-modified", NULL);

      if (pr_table_add(cmd2->notes, "mod_xfer.file-modified",
          pstrdup(cmd2->pool, "true"), 0) < 0) {
        if (errno != EEXIST) {
          pr_log_pri(PR_LOG_NOTICE,
            "notice: error adding 'mod_xfer.file-modified' note: %s",
            strerror(errno));
        }
      }
    }
  }

  pr_fs_clear_cache2(path);
  if (exists2(fxp->pool, path)) {
    /* draft-ietf-secsh-filexfer-06.txt, section 7.1.1 specifically
     * states that any attributes in a OPEN request are ignored if the
     * file already exists.
     */
    if (attr_flags & SSH2_FX_ATTR_PERMISSIONS) {
      pr_trace_msg(trace_channel, 15,
        "OPEN request for existing path, ignoring perms sent by client");
      attr_flags &= ~SSH2_FX_ATTR_PERMISSIONS;
    }

    if ((attr_flags & SSH2_FX_ATTR_UIDGID) ||
        (attr_flags & SSH2_FX_ATTR_OWNERGROUP)) {
      pr_trace_msg(trace_channel, 15,
        "OPEN request for existing path, ignoring ownership sent by client");
      attr_flags &= ~SSH2_FX_ATTR_UIDGID;
      attr_flags &= ~SSH2_FX_ATTR_OWNERGROUP;
    }
  }

  /* We automatically add the O_NONBLOCK flag to the set of open() flags
   * in order to deal with writing to a FIFO whose other end may not be
   * open.  Then, after a successful open, we return the file to blocking
   * mode.
   */
  fh = pr_fsio_open(hiddenstore_path ? hiddenstore_path : path,
    open_flags|O_NONBLOCK);
  if (fh == NULL) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    (void) pr_trace_msg("fileperms", 1, "OPEN, user '%s' (UID %s, GID %s): "
      "error opening '%s': %s", session.user,
      pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
      hiddenstore_path ? hiddenstore_path : path, strerror(xerrno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error opening '%s': %s", hiddenstore_path ? hiddenstore_path : path,
      strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    if (cmd2 != NULL) {
      pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
      fxp_cmd_note_file_status(cmd2, "failed");
      fxp_cmd_dispatch_err(cmd2);
    }

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_note_file_status(cmd, "failed");
    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  memset(&st, 0, sizeof(st));
  if (pr_fsio_fstat(fh, &st) < 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "fstat error on '%s' (fd %d): %s", path, fh->fh_fd, strerror(errno));
  }

#ifdef S_ISFIFO
  /* The path in question might be a FIFO.  The FIFO case requires some special
   * handling, modulo any IgnoreFIFOs SFTPOption that might be in effect.
   */
  if (S_ISFIFO(st.st_mode) &&
      (sftp_opts & SFTP_OPT_IGNORE_FIFOS)) {
    uint32_t status_code;
    const char *reason;
    int xerrno = EPERM;

    (void) pr_fsio_close(fh);

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error opening FIFO '%s': %s (IgnoreFIFOs SFTPOption in effect)",
      hiddenstore_path ? hiddenstore_path : path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    if (cmd2 != NULL) {
      pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
      fxp_cmd_note_file_status(cmd2, "failed");
      fxp_cmd_dispatch_err(cmd2);
    }

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_note_file_status(cmd, "failed");
    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }
#endif /* S_ISFIFO */

  if (pr_fsio_set_block(fh) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error setting fd %d (file '%s') as blocking: %s", fh->fh_fd,
      fh->fh_path, strerror(errno));
  }
 
  attr_flags = fxp_attrs_clear_unsupported(attr_flags);

  /* If the SFTPOption for ignoring perms for SFTP uploads is set, handle
   * it by clearing the SSH2_FX_ATTR_PERMISSIONS flag.
   */
  if ((sftp_opts & SFTP_OPT_IGNORE_SFTP_UPLOAD_PERMS) &&
      (attr_flags & SSH2_FX_ATTR_PERMISSIONS)) {
    pr_trace_msg(trace_channel, 7, "SFTPOption 'IgnoreSFTPUploadPerms' "
      "configured, ignoring perms sent by client");
    attr_flags &= ~SSH2_FX_ATTR_PERMISSIONS;
  }

  /* If the SFTPOption for ignoring xattrs for SFTP uploads is set, handle it
   * by clearing the SSH2_FX_ATTR_EXTENDED flag.
   */
  if ((sftp_opts & SFTP_OPT_IGNORE_SFTP_UPLOAD_XATTRS) &&
      (attr_flags & SSH2_FX_ATTR_EXTENDED)) {
    pr_trace_msg(trace_channel, 7,
      "SFTPOption 'IgnoreSFTPUploadExtendedAttributes' configured, "
      "ignoring xattrs sent by client");
    attr_flags &= ~SSH2_FX_ATTR_EXTENDED;
  }

  /* If the client provided a suggested size in the OPEN, ignore it.
   * Trying to honor the suggested size by truncating the file here can
   * cause problems, as when the client is resuming a transfer and the
   * resumption fails; the file would then be worse off than before due to the
   * truncation.  See:
   *
   *  http://winscp.net/tracker/show_bug.cgi?id=351
   *
   * The truncation isn't really needed anyway, since the ensuing READ/WRITE
   * requests will contain the offsets into the file at which to begin
   * reading/write the file contents.
   *
   * However, if the size is provided, we should at least record it in the
   * handle structure.  In the case of an upload, we can compare the size of
   * file, at CLOSE time, with the size that was provided here.  If the size
   * of the file at CLOSE is less than the size sent here, we could log it
   * as an incomplete upload.  Not all clients will provide the size attribute,
   * for those that do, it can be useful.
   */

  attr_flags &= ~SSH2_FX_ATTR_SIZE;

  res = fxp_attrs_set(fh, fh->fh_path, attrs, attr_flags, xattrs, &buf,
    &buflen, fxp);
  if (res < 0) {
    int xerrno = errno;

    pr_fsio_close(fh);

    if (cmd2 != NULL) {
      pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
      fxp_cmd_note_file_status(cmd2, "failed");
      fxp_cmd_dispatch_err(cmd2);
    }

    fxp_cmd_note_file_status(cmd, "failed");
    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if ((open_flags & O_WRONLY) ||
      (open_flags & O_RDWR)) {
    /* Handle any possible UserOwner/GroupOwner directives for uploaded
     * files.
     */
    if (sftp_misc_chown_file(fxp->pool, fh) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error changing ownership on file '%s': %s", fh->fh_path,
        strerror(errno));
    }
  }

  fxh = fxp_handle_create(fxp_pool);
  if (fxh == NULL) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error creating SFTP handle for '%s': %s", fh->fh_path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    if (cmd2 != NULL) {
      pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
      fxp_cmd_note_file_status(cmd2, "failed");
      fxp_cmd_dispatch_err(cmd2);
    }

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_note_file_status(cmd, "failed");
    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  fxh->fh = fh;
  fxh->fh_flags = open_flags;
  fxh->fh_existed = file_existed;
  memcpy(fxh->fh_st, &st, sizeof(struct stat));

  if (hiddenstore_path) {
    fxh->fh_real_path = pstrdup(fxh->pool, path);
  }

  if (fxp_handle_add(fxp->channel_id, fxh) < 0) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    buf = ptr;
    buflen = bufsz;

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    pr_fsio_close(fh);
    destroy_pool(fxh->pool);

    if (cmd2 != NULL) {
      pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
      fxp_cmd_note_file_status(cmd2, "failed");
      fxp_cmd_dispatch_err(cmd2);
    }

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_note_file_status(cmd, "failed");
    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8, "sending response: HANDLE %s", fxh->name);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_HANDLE);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);
  sftp_msg_write_string(&buf, &buflen, fxh->name);

  /* Clear out any transfer-specific data. */
  if (session.xfer.p) {
    destroy_pool(session.xfer.p);
  }
  memset(&session.xfer, 0, sizeof(session.xfer));

  session.xfer.p = make_sub_pool(fxp_pool);
  pr_pool_tag(session.xfer.p, "SFTP session transfer pool");
  session.xfer.path = pstrdup(session.xfer.p, orig_path);
  memset(&session.xfer.start_time, 0, sizeof(session.xfer.start_time));
  gettimeofday(&session.xfer.start_time, NULL);

  if ((open_flags & O_APPEND) ||
      (open_flags & O_WRONLY) ||
      (open_flags & O_RDWR)) {
    session.xfer.direction = PR_NETIO_IO_RD;

  } else if (open_flags == O_RDONLY) {
    session.xfer.direction = PR_NETIO_IO_WR;
  }

  pr_timer_remove(PR_TIMER_STALLED, ANY_MODULE);

  timeout_stalled = pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED);
  if (timeout_stalled > 0) {
    pr_timer_add(timeout_stalled, PR_TIMER_STALLED, NULL,
      fxp_timeout_stalled_cb, "TimeoutStalled");
  }

  /* Add a note containing the file handle for logging (Bug#3707). */
  fxp_set_filehandle_note(cmd, fxh);

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_opendir(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *path, *vpath;
  uint32_t buflen, bufsz;
  int timeout_stalled;
  void *dirh;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  cmd_rec *cmd, *cmd2;
  struct stat st;

  path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    path = sftp_utf8_decode_str(fxp->pool, path);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "OPENDIR", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", path, NULL, NULL);

  pr_proctitle_set("%s - %s: OPENDIR %s", session.user, session.proc_prefix,
    path);

  pr_trace_msg(trace_channel, 7, "received request: OPENDIR %s", path);

  if (strlen(path) == 0) {
    /* Use the default directory if the path is empty. */
    path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty path given in OPENDIR request, using '%s'", path);
  }

  cmd = fxp_cmd_alloc(fxp->pool, "OPENDIR", path);
  cmd->cmd_class = CL_DIRS|CL_SFTP;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "OPENDIR of '%s' blocked by '%s' handler", path, (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = cmd->arg;

  pr_fs_clear_cache2(path);
  if (pr_fsio_lstat(path, &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      char link_path[PR_TUNABLE_PATH_MAX];
      int len;

      memset(link_path, '\0', sizeof(link_path));
      len = dir_readlink(fxp->pool, path, link_path, sizeof(link_path)-1,
        PR_DIR_READLINK_FL_HANDLE_REL_PATH);
      if (len > 0) {
        link_path[len] = '\0';
        path = pstrdup(fxp->pool, link_path);
      }
    }
  }

  path = dir_best_path(fxp->pool, path);
  if (path == NULL) {
    int xerrno = EACCES;
    const char *reason;
    uint32_t status_code;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "OPENDIR request denied: unable to access path '%s'", cmd->arg);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
       xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (!dir_check(fxp->pool, cmd, G_DIRS, path, NULL)) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "OPENDIR of '%s' blocked by <Limit> configuration", path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  cmd2 = fxp_cmd_alloc(fxp->pool, C_MLSD, path);
  cmd2->cmd_class = CL_DIRS;
  cmd2->cmd_id = pr_cmd_get_id(C_MLSD);

  if (pr_cmd_dispatch_phase(cmd2, PRE_CMD, 0) < 0) {
    int xerrno = errno;
    const char *reason;
    uint32_t status_code;

    /* One of the PRE_CMD phase handlers rejected the command. */
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "OPENDIR command for '%s' blocked by '%s' handler", path,
      (char *) cmd2->argv[0]);

    /* Hopefully the command handlers set an appropriate errno value.  If
     * they didn't, however, we need to be prepared with a fallback.
     */
    if (xerrno != ENOENT &&
        xerrno != EACCES &&
        xerrno != EPERM &&
        xerrno != EINVAL) {
      xerrno = EACCES;
    }

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
       xerrno);

    pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = cmd2->arg;

  vpath = dir_canonical_vpath(fxp->pool, path);
  if (vpath == NULL) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error resolving '%s': %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  path = vpath;

  dirh = pr_fsio_opendir(path);
  if (dirh == NULL) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    (void) pr_trace_msg("fileperms", 1, "OPENDIR, user '%s' (UID %s, "
      "GID %s): error opening '%s': %s", session.user,
      pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
      path, strerror(xerrno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error opening '%s': %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  fxh = fxp_handle_create(fxp_pool);
  if (fxh == NULL) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error creating SFTP handle for '%s': %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  fxh->dirh = dirh;
  fxh->dir = pstrdup(fxh->pool, path);

  if (fxp_handle_add(fxp->channel_id, fxh) < 0) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    buf = ptr;
    buflen = bufsz;

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    if (pr_fsio_closedir(dirh) < 0) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error closing directory '%s': %s", fxh->dir, strerror(xerrno));
    }

    destroy_pool(fxh->pool);

    pr_response_add_err(R_451, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8, "sending response: HANDLE %s",
    fxh->name);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_HANDLE);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);
  sftp_msg_write_string(&buf, &buflen, fxh->name);

  /* If there is any existing transfer-specific data, leave it alone.
   *
   * Unlike FTP, SFTP allows for file downloads whilst in the middle of
   * a directory listing.  Thus this OPENDIR could arrive while a file
   * is being read/written.  Assume that the per-file stats are more
   * important.
   */
  if (session.xfer.p == NULL) {
    memset(&session.xfer, 0, sizeof(session.xfer));

    session.xfer.p = make_sub_pool(fxp_pool);
    pr_pool_tag(session.xfer.p, "SFTP session transfer pool");
    memset(&session.xfer.start_time, 0, sizeof(session.xfer.start_time));
    gettimeofday(&session.xfer.start_time, NULL);
    session.xfer.direction = PR_NETIO_IO_WR;
  }

  pr_timer_remove(PR_TIMER_STALLED, ANY_MODULE);

  timeout_stalled = pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED);
  if (timeout_stalled > 0) {
    pr_timer_add(timeout_stalled, PR_TIMER_STALLED, NULL,
      fxp_timeout_stalled_cb, "TimeoutStalled");
  }

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_read(struct fxp_packet *fxp) {
  unsigned char *buf, *data = NULL, *ptr;
  char *file, *name, *ptr2;
  int res;
  uint32_t buflen, bufsz, datalen;
  uint64_t offset;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  cmd_rec *cmd, *cmd2;
  pr_buffer_t *pbuf;

  name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  offset = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);
  datalen = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

#if 0
  /* XXX This doesn't appear to be needed now.  But I'll keep it around,
   * just in case some buggy client needs this treatment.
   */
  if (datalen > max_readsz) {
    pr_trace_msg(trace_channel, 8,
      "READ requested len %lu exceeds max (%lu), truncating",
      (unsigned long) datalen, (unsigned long) max_readsz);
    datalen = max_readsz;
  }
#endif

  cmd = fxp_cmd_alloc(fxp->pool, "READ", name);
  cmd->cmd_class = CL_READ|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "READ", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", name, NULL, NULL);

  pr_proctitle_set("%s - %s: READ %s %" PR_LU " %lu", session.user,
    session.proc_prefix, name, (pr_off_t) offset, (unsigned long) datalen);

  pr_trace_msg(trace_channel, 7, "received request: READ %s %" PR_LU " %lu",
    name, (pr_off_t) offset, (unsigned long) datalen);

  buflen = bufsz = datalen + 64;
  buf = ptr = palloc(fxp->pool, bufsz);

  fxh = fxp_handle_get(name);
  if (fxh == NULL) {
    uint32_t status_code;

    pr_trace_msg(trace_channel, 17,
      "%s: unable to find handle for name '%s': %s", (char *) cmd->argv[0],
      name, strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->fh == NULL) {
    uint32_t status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  /* Add a note containing the file handle for logging (Bug#3707). */
  fxp_set_filehandle_note(cmd, fxh);

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", fxh->fh->fh_path, NULL, NULL);

  if ((off_t) offset > fxh->fh_st->st_size) {
    uint32_t status_code;
    const char *reason;
    int xerrno = EOF;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "requested read offset (%" PR_LU " bytes) greater than size of "
      "'%s' (%" PR_LU " bytes)", (pr_off_t) offset, fxh->fh->fh_path,
      (pr_off_t) fxh->fh_st->st_size);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, "End of file",
      xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_XFER_SIZE, fxh->fh_st->st_size,
    PR_SCORE_XFER_DONE, (off_t) offset,
    NULL);

  /* Trim the full path to just the filename, for our RETR command. */
  ptr2 = strrchr(fxh->fh->fh_path, '/');
  if (ptr2 != NULL &&
      ptr2 != fxh->fh->fh_path) {
    file = pstrdup(fxp->pool, ptr2 + 1);

  } else {
    file = fxh->fh->fh_path;
  }

  cmd2 = fxp_cmd_alloc(fxp->pool, C_RETR, file);
  cmd2->cmd_class = CL_READ|CL_SFTP;

  if (!dir_check(fxp->pool, cmd, G_READ, fxh->fh->fh_path, NULL)) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "READ of '%s' blocked by <Limit> configuration", fxh->fh->fh_path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* XXX Check MaxRetrieveFileSize */

  if (fxp_path_pass_regex_filters(fxp->pool, "READ", fxh->fh->fh_path) < 0) {
    uint32_t status_code;
    const char *reason;

    status_code = fxp_errno2status(errno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (S_ISREG(fxh->fh_st->st_mode)) {
    if (pr_fsio_lseek(fxh->fh, offset, SEEK_SET) < 0) {
      uint32_t status_code;
      const char *reason;
      int xerrno = errno;

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error seeking to offset (%" PR_LU " bytes) for '%s': %s",
        (pr_off_t) offset, fxh->fh->fh_path, strerror(xerrno));

      status_code = fxp_errno2status(xerrno, &reason);

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
        "('%s' [%d])", (unsigned long) status_code, reason,
        xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        reason, NULL);

      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);
  
      return fxp_packet_write(resp);

    } else {
      off_t *file_offset;

      /* Stash the offset at which we're reading from this file. */
      file_offset = palloc(cmd->pool, sizeof(off_t));
      *file_offset = (off_t) offset;
      (void) pr_table_add(cmd->notes, "mod_xfer.file-offset", file_offset,
        sizeof(off_t));

      /* No error. */
      errno = 0;
    }
  }

  cmd2 = fxp_cmd_alloc(fxp->pool, C_RETR, NULL);
  pr_throttle_init(cmd2);

  if (datalen) {
    data = palloc(fxp->pool, datalen);
  }

  res = pr_fsio_read(fxh->fh, (char *) data, datalen);

  if (pr_data_get_timeout(PR_DATA_TIMEOUT_NO_TRANSFER) > 0) {
    pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
  }

  if (pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED) > 0) {
    pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
  }

  if (res <= 0) {
    uint32_t status_code;
    const char *reason;
    int xerrno;

    if (res < 0) {
      xerrno = errno;

      (void) pr_trace_msg("fileperms", 1, "READ, user '%s' (UID %s, GID %s): "
        "error reading from '%s': %s", session.user,
        pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
        fxh->fh->fh_path, strerror(xerrno));

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error reading from '%s': %s", fxh->fh->fh_path, strerror(xerrno));

      errno = xerrno;

    } else {
      /* Assume EOF */
      pr_throttle_pause(offset, TRUE);
      xerrno = EOF;
    }

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    if (xerrno != EOF) {
      fxp_cmd_dispatch_err(cmd);

    } else {
      fxp_cmd_dispatch(cmd);
    }

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_throttle_pause(offset, FALSE);

  pr_trace_msg(trace_channel, 8, "sending response: DATA (%lu bytes)",
    (unsigned long) res);

  pbuf = pcalloc(fxp->pool, sizeof(pr_buffer_t));
  pbuf->buf = (char *) data;
  pbuf->buflen = res;
  pbuf->current = pbuf->buf;
  pbuf->remaining = 0;
  pr_event_generate("mod_sftp.sftp.data-write", pbuf);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_DATA);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);
  sftp_msg_write_data(&buf, &buflen, data, res, TRUE);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  fxh->fh_bytes_xferred += res;
  session.xfer.total_bytes += res;
  session.total_bytes += res;

  fxp_cmd_dispatch(cmd);

  res = fxp_packet_write(resp);
  return res;
}

static int fxp_handle_readdir(struct fxp_packet *fxp) {
  register unsigned int i;
  unsigned char *buf;
  char *cmd_name, *name;
  uint32_t attr_flags, buflen, curr_packet_pathsz = 0, max_packetsz;
  struct dirent *dent;
  struct fxp_buffer *fxb;
  struct fxp_dirent **paths;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  array_header *path_list;
  cmd_rec *cmd;
  int have_error = FALSE, have_eod = TRUE, res;
  mode_t *fake_mode = NULL;
  const char *fake_user = NULL, *fake_group = NULL, *vwd = NULL;

  name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

  cmd = fxp_cmd_alloc(fxp->pool, "READDIR", name);
  cmd->cmd_class = CL_DIRS|CL_SFTP;
  cmd->group = G_DIRS;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "READDIR", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", name, NULL, NULL);

  pr_proctitle_set("%s - %s: READDIR %s", session.user, session.proc_prefix,
    name);

  pr_trace_msg(trace_channel, 7, "received request: READDIR %s", name);

  /* XXX What's a good size here? */

  fxb = pcalloc(fxp->pool, sizeof(struct fxp_buffer));

  max_packetsz = sftp_channel_get_max_packetsz();
  fxb->bufsz = buflen = max_packetsz;
  fxb->ptr = buf = palloc(fxp->pool, fxb->bufsz);

  fxh = fxp_handle_get(name);
  if (fxh == NULL) {
    uint32_t status_code;

    pr_trace_msg(trace_channel, 17,
      "%s: unable to find handle for name '%s': %s", (char *) cmd->argv[0],
      name, strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->dirh == NULL) {
    uint32_t status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", fxh->dir, NULL, NULL);

  path_list = make_array(fxp->pool, 5, sizeof(struct fxp_dirent *));

  cmd_name = cmd->argv[0];

  /* If blocked by <Limit LIST>/<Limit NLST>, return EOF immediately. */
  pr_cmd_set_name(cmd, C_LIST);
  res = dir_check(fxp->pool, cmd, cmd->group, (char *) fxh->dir, NULL);
  if (res == 0) {
    have_error = TRUE;
  }

  if (!have_error) {
    pr_cmd_set_name(cmd, C_NLST);
    res = dir_check(fxp->pool, cmd, cmd->group, (char *) fxh->dir, NULL);
    if (res == 0) {
      have_error = TRUE;
    }
  }

  pr_cmd_set_name(cmd, "READDIR");
  res = dir_check(fxp->pool, cmd, cmd->group, (char *) fxh->dir, NULL);
  if (res == 2) {
    /* Explicitly allowed by <Limit READDIR> configuration. */
    have_error = FALSE;

  } else if (res == 0) {
    have_error = TRUE;
  }

  if (have_error) {
    uint32_t status_code = SSH2_FX_EOF;
 
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "READDIR of '%s' blocked by <Limit %s> configuration", fxh->dir,
      (char *) cmd->argv[0]);

    pr_cmd_set_name(cmd, cmd_name);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_cmd_set_name(cmd, cmd_name);

  /* Change into the directory being read, so that ".", "..", and relative
   * paths (e.g. for symlinks) get resolved properly.
   *
   * We need to dup the string returned by pr_fs_getvwd(), since it returns
   * a pointer to a static string which is changed by the call we make
   * to pr_fsio_chdir().
   */
  vwd = pstrdup(fxp->pool, pr_fs_getvwd());

  res = pr_fsio_chdir(fxh->dir, FALSE);
  if (res < 0) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to chdir to '%s': %s", (char *) fxh->dir, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  fake_mode = get_param_ptr(get_dir_ctxt(fxp->pool, (char *) fxh->dir),
    "DirFakeMode", FALSE);

  fake_user = get_param_ptr(get_dir_ctxt(fxp->pool, (char *) fxh->dir),
    "DirFakeUser", FALSE);
  if (fake_user != NULL &&
      strncmp(fake_user, "~", 2) == 0) {
    fake_user = session.user;
  }

  fake_group = get_param_ptr(get_dir_ctxt(fxp->pool, (char *) fxh->dir),
    "DirFakeGroup", FALSE);
  if (fake_group != NULL &&
      strncmp(fake_group, "~", 2) == 0) {
    fake_group = session.group;
  }

  while ((dent = pr_fsio_readdir(fxh->dirh)) != NULL) {
    char *real_path;
    struct fxp_dirent *fxd;
    uint32_t curr_packetsz, max_entry_metadata, max_entrysz;
    size_t dent_len;

    pr_signals_handle();

    /* How much non-path data do we expect to be associated with this entry? */
#ifdef PR_USE_XATTR
    /* Note that the "extra space" to allocate for extended attributes is
     * currently a bit of a guess.  Initially, this was 4K; that was causing
     * slower directory listings due to the need for more READDIR requests,
     * since we were sending fewer entries back (limited by the max packet
     * size) per READDIR request.
     *
     * Now, we are trying 1K, and will see how that does.
     */
    max_entry_metadata = 1024;
#else
    max_entry_metadata = 256;
#endif /* PR_USE_XATTR */

    max_entrysz = (PR_TUNABLE_PATH_MAX + 1 + max_entry_metadata);

    /* Do not expand/resolve dot directories; it will be handled automatically
     * lower down in the ACL-checking code.  Plus, this allows regex filters
     * that rely on the dot directory name to work properly.
     */
    if (!is_dotdir(dent->d_name)) {
      real_path = pdircat(fxp->pool, fxh->dir, dent->d_name, NULL);

    } else {
      real_path = pstrdup(fxp->pool, dent->d_name);
    }

    fxd = fxp_get_dirent(fxp->pool, cmd, real_path, fake_mode);
    if (fxd == NULL) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 3,
        "unable to obtain directory listing for '%s': %s", real_path,
        strerror(xerrno));

      continue;
    }

    dent_len = strlen(dent->d_name);
    fxd->client_path = pstrndup(fxp->pool, dent->d_name, dent_len);
    curr_packet_pathsz += (dent_len + 1);
    
    *((struct fxp_dirent **) push_array(path_list)) = fxd;

    /* We determine the number of entries to send in this packet based on
     * the maximum packet size and the max entry size.
     *
     * We assume that each entry will need up to PR_TUNABLE_PATH_MAX+1 bytes for
     * the filename, and max_entry_metadata bytes of associated data.
     *
     * We have the total number of entries for this message when there is less
     * than enough space for one more maximum-sized entry.
     */

    curr_packetsz = curr_packet_pathsz +
      (path_list->nelts * max_entry_metadata);
    if ((max_packetsz - curr_packetsz) <= max_entrysz) {
      have_eod = FALSE;
      break;
    }
  }

  if (pr_data_get_timeout(PR_DATA_TIMEOUT_NO_TRANSFER) > 0) {
    pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
  }

  if (pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED) > 0) {
    pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
  }

  /* Now make sure we switch back to the directory where we were. */
  res = pr_fsio_chdir(vwd, FALSE);
  if (res < 0) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to chdir to '%s': %s", vwd, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (path_list->nelts == 0) {
    /* We have reached the end of the directory entries; send an EOF. */
    uint32_t status_code = SSH2_FX_EOF;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8, "sending response: NAME (%lu count)",
    (unsigned long) path_list->nelts);

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_NAME);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);
  sftp_msg_write_int(&buf, &buflen, path_list->nelts);

  fxb->buf = buf;
  fxb->buflen = buflen;
  paths = path_list->elts;

  /* For READDIR requests, since they do NOT contain a flags field for clients
   * to express which attributes they want, we ASSUME some standard fields.
   */

  if (fxp_session->client_version <= 3) {
    attr_flags = SSH2_FX_ATTR_SIZE|SSH2_FX_ATTR_UIDGID|SSH2_FX_ATTR_PERMISSIONS|
      SSH2_FX_ATTR_ACMODTIME;

  } else {
    attr_flags = SSH2_FX_ATTR_SIZE|SSH2_FX_ATTR_PERMISSIONS|
      SSH2_FX_ATTR_ACCESSTIME|SSH2_FX_ATTR_MODIFYTIME|SSH2_FX_ATTR_OWNERGROUP;
  }

  /* The FX_ATTR_LINK_COUNT attribute was defined in
   * draft-ietf-secsh-filexfer-06, which is SFTP protocol version 6.
   */
  if (fxp_session->client_version >= 6) {
    attr_flags |= SSH2_FX_ATTR_LINK_COUNT;

    /* The FX_ATTR_EXTENDED attribute was defined in
     * draft-ietf-secsh-filexfer-02, which is SFTP protocol version 3.
     * However, many SFTP clients may not be prepared for handling these.
     * Thus we CHOOSE to only provide these extended attributes, if supported,
     * to protocol version 6 clients.
     */
#ifdef PR_USE_XATTR
    if (!(fxp_fsio_opts & PR_FSIO_OPT_IGNORE_XATTR)) {
      attr_flags |= SSH2_FX_ATTR_EXTENDED;
    }
#endif /* PR_USE_XATTR */
  }

  for (i = 0; i < path_list->nelts; i++) {
    uint32_t name_len = 0;

    name_len = fxp_name_write(fxp->pool, fxb, paths[i]->client_path,
      paths[i]->st, attr_flags, fake_user, fake_group);

    pr_trace_msg(trace_channel, 19, "READDIR: FXP_NAME entry size: %lu bytes",
      (unsigned long) name_len);
  }

  /* fxp_name_write will have changed the values stashed in the buffer. */
  buf = fxb->buf;
  buflen = fxb->buflen;

  if (fxp_session->client_version > 5) {
    sftp_msg_write_bool(&buf, &buflen, have_eod ? TRUE : FALSE);
  }

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = fxb->ptr;
  resp->payload_sz = (fxb->bufsz - buflen);

  session.xfer.total_bytes += resp->payload_sz;
  session.total_bytes += resp->payload_sz;

  fxp_cmd_dispatch(cmd);

  return fxp_packet_write(resp);
}

static int fxp_handle_readlink(struct fxp_packet *fxp) {
  char data[PR_TUNABLE_PATH_MAX + 1];
  unsigned char *buf;
  char *path, *resolved_path;
  int res;
  uint32_t buflen;
  struct fxp_buffer *fxb;
  struct fxp_packet *resp;
  cmd_rec *cmd;

  path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    path = sftp_utf8_decode_str(fxp->pool, path);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "READLINK", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", path, NULL, NULL);

  pr_proctitle_set("%s - %s: READLINK %s", session.user, session.proc_prefix,
    path);

  pr_trace_msg(trace_channel, 7, "received request: READLINK %s", path);

  if (strlen(path) == 0) {
    /* Use the default directory if the path is empty. */
    path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty path given in READLINK request, using '%s'", path);
  }

  cmd = fxp_cmd_alloc(fxp->pool, "READLINK", path);
  cmd->cmd_class = CL_READ|CL_SFTP;

  fxb = pcalloc(fxp->pool, sizeof(struct fxp_buffer));
  fxb->bufsz = buflen = FXP_RESPONSE_NAME_DEFAULT_SZ;
  fxb->ptr = buf = palloc(fxp->pool, fxb->bufsz);

  if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "READLINK of '%s' blocked by '%s' handler", path, (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = cmd->arg;
  pr_fs_clear_cache2(path);

  resolved_path = dir_best_path(fxp->pool, path);
  if (resolved_path == NULL) {
    int xerrno = EACCES;
    const char *reason;
    uint32_t status_code;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "READLINK request denied: unable to access path '%s'", cmd->arg);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
       xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (!dir_check(fxp->pool, cmd, G_READ, resolved_path, NULL)) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "READLINK of '%s' (resolved to '%s') blocked by <Limit %s> configuration",
      path, resolved_path, (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  memset(data, '\0', sizeof(data));

  /* Note: do NOT use the resolved_path variable here, as it will have
   * resolved by following any symlinks; readlink(2) would then return EINVAL
   * for reading a non-symlink path.
   */
  res = dir_readlink(fxp->pool, path, data, sizeof(data) - 1,
    PR_DIR_READLINK_FL_HANDLE_REL_PATH);
  if (res < 0) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    buf = fxb->ptr;
    buflen = fxb->bufsz;

    status_code = fxp_errno2status(xerrno, &reason);

    (void) pr_trace_msg("fileperms", 1, "READLINK, user '%s' (UID %s, "
      "GID %s): error using readlink() on  '%s': %s", session.user,
      pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
      path, strerror(xerrno));

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

  } else {
    struct stat st;
    const char *fake_user = NULL, *fake_group = NULL;

    memset(&st, 0, sizeof(struct stat));

    data[res] = '\0';

    pr_trace_msg(trace_channel, 8, "sending response: NAME 1 %s %s",
      data, fxp_strattrs(fxp->pool, &st, NULL));

    sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_NAME);
    sftp_msg_write_int(&buf, &buflen, fxp->request_id);
    sftp_msg_write_int(&buf, &buflen, 1);

    fake_user = get_param_ptr(get_dir_ctxt(fxp->pool, path), "DirFakeUser",
      FALSE);
    if (fake_user != NULL &&
        strncmp(fake_user, "~", 2) == 0) {
      fake_user = session.user;
    }

    fake_group = get_param_ptr(get_dir_ctxt(fxp->pool, path), "DirFakeGroup",
      FALSE);
    if (fake_group != NULL &&
        strncmp(fake_group, "~", 2) == 0) {
      fake_group = session.group;
    }

    fxb->buf = buf;
    fxb->buflen = buflen;

    fxp_name_write(fxp->pool, fxb, data, &st, 0, fake_user, fake_group);

    buf = fxb->buf;
    buflen = fxb->buflen;

    fxp_cmd_dispatch(cmd);
  }

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = fxb->ptr;
  resp->payload_sz = (fxb->bufsz - buflen);

  return fxp_packet_write(resp);
}

static void fxp_trace_v6_realpath_flags(pool *p, unsigned char flags,
    int client_sent) {
  char *flags_str = "";
  int trace_level = 15;

  if (pr_trace_get_level(trace_channel) < trace_level) {
    return;
  }

  switch (flags) {
    case SSH2_FXRP_NO_CHECK:
      flags_str = "FX_REALPATH_NO_CHECK";
      break;

    case SSH2_FXRP_STAT_IF:
      flags_str = "FX_REALPATH_STAT_IF";
      break;

    case SSH2_FXRP_STAT_ALWAYS:
      flags_str = "FX_REALPATH_STAT_ALWAYS";
      break;
  }

  pr_trace_msg(trace_channel, trace_level, "REALPATH flags = %s (%s)",
    flags_str, client_sent == TRUE ? "explicit" : "default");
}

static int fxp_handle_realpath(struct fxp_packet *fxp) {
  int res, xerrno;
  unsigned char *buf, realpath_flags = SSH2_FXRP_NO_CHECK;
  char *path;
  uint32_t buflen;
  struct stat st;
  struct fxp_buffer *fxb;
  struct fxp_packet *resp;
  cmd_rec *cmd;

  path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    path = sftp_utf8_decode_str(fxp->pool, path);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "REALPATH", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", path, NULL, NULL);

  pr_proctitle_set("%s - %s: REALPATH %s", session.user, session.proc_prefix,
    path);

  pr_trace_msg(trace_channel, 7, "received request: REALPATH %s", path);

  if (strlen(path) == 0) {
    /* Use the default directory if the path is empty. */
    path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty path given in REALPATH request, using '%s'", path);
  }

  cmd = fxp_cmd_alloc(fxp->pool, "REALPATH", path);
  cmd->cmd_class = CL_INFO|CL_SFTP;

  if (fxp_session->client_version >= 6) {
    /* See Section 8.9 of:
     *
     *  http://tools.ietf.org/id/draft-ietf-secsh-filexfer-13.txt
     *
     * for the semantics and defaults of these crazy flags.
     */

    if (fxp->payload_sz >= sizeof(char)) {
      char *composite_path = NULL;

      realpath_flags = sftp_msg_read_byte(fxp->pool, &fxp->payload,
        &fxp->payload_sz);
      fxp_trace_v6_realpath_flags(fxp->pool, realpath_flags, TRUE);

      if (fxp->payload_sz > 0) {
        composite_path = sftp_msg_read_string(fxp->pool, &fxp->payload,
          &fxp->payload_sz);

        /* XXX One problem with the most recent SFTP Draft is that it does NOT
         * include a count of the number of composite-paths that the client
         * may send.  The format of the REALPATH request, currently, only allows
         * for one composite-path element; the description of this feature
         * implies that multiple such composite-path elements could be supplied.
         * Sigh.  Maybe it's meant to a blob of strings?  Or we keep reading
         * a string until the remaining payload size is zero?
         */
        pr_trace_msg(trace_channel, 13,
          "REALPATH request set composite-path: '%s'", composite_path);
      }

    } else {
      fxp_trace_v6_realpath_flags(fxp->pool, realpath_flags, FALSE);
    }
  }

  fxb = pcalloc(fxp->pool, sizeof(struct fxp_buffer));
  fxb->bufsz = buflen = FXP_RESPONSE_NAME_DEFAULT_SZ;
  fxb->ptr = buf = palloc(fxp->pool, fxb->bufsz);

  res = pr_cmd_dispatch_phase(cmd, PRE_CMD, 0);
  if (res < 0) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "REALPATH of '%s' blocked by '%s' handler", path, (char *) cmd->argv[0]);

    if (fxp_session->client_version <= 5 ||
        (fxp_session->client_version >= 6 &&
         realpath_flags != SSH2_FXRP_NO_CHECK)) {
      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
        (unsigned long) status_code, fxp_strerror(status_code));

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        fxp_strerror(status_code), NULL);

    } else {
      uint32_t attr_flags = 0;

      memset(&st, 0, sizeof(st));
      st.st_uid = (uid_t) -1;
      st.st_gid = (gid_t) -1;
  
      pr_trace_msg(trace_channel, 8, "sending response: NAME 1 %s %s",
        path, fxp_strattrs(fxp->pool, &st, &attr_flags));

      sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_NAME);
      sftp_msg_write_int(&buf, &buflen, fxp->request_id);
      sftp_msg_write_int(&buf, &buflen, 1);

      fxb->buf = buf;
      fxb->buflen = buflen;

      fxp_name_write(fxp->pool, fxb, path, &st, 0, "nobody", "nobody");

      buf = fxb->buf;
      buflen = fxb->buflen;
    }

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = cmd->arg;

  if (strncmp(path, ".", 2) == 0) {
    /* The client is asking about the current working directory.  Easy. */
    path = (char *) pr_fs_getvwd();

  } else {
    char *vpath;

    vpath = dir_realpath(fxp->pool, path);
    if (vpath == NULL) {
      uint32_t status_code;
      const char *reason;

      xerrno = errno;

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error resolving '%s': %s", path, strerror(xerrno));

      status_code = fxp_errno2status(xerrno, &reason);

      if (fxp_session->client_version <= 5 ||
          (fxp_session->client_version >= 6 &&
           realpath_flags != SSH2_FXRP_NO_CHECK)) {
        pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
          "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
          xerrno);

        fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
          reason, NULL);

      } else {
        uint32_t attr_flags = 0;

        memset(&st, 0, sizeof(st));
        st.st_uid = (uid_t) -1;
        st.st_gid = (gid_t) -1;

        pr_trace_msg(trace_channel, 8, "sending response: NAME 1 %s %s",
          path, fxp_strattrs(fxp->pool, &st, &attr_flags));

        sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_NAME);
        sftp_msg_write_int(&buf, &buflen, fxp->request_id);
        sftp_msg_write_int(&buf, &buflen, 1);

        fxb->buf = buf;
        fxb->buflen = buflen;

        fxp_name_write(fxp->pool, fxb, path, &st, 0, "nobody", "nobody");

        buf = fxb->buf;
        buflen = fxb->buflen;
      }

      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = fxb->ptr;
      resp->payload_sz = (fxb->bufsz - buflen);

      return fxp_packet_write(resp);
    }

    pr_trace_msg(trace_channel, 15,
      "resolved client-sent path '%s' to local path '%s'", path, vpath);
    path = vpath;
  }

  /* Force a full lookup. */
  pr_fs_clear_cache2(path);
  if (!dir_check_full(fxp->pool, cmd, G_DIRS, path, NULL)) {
    uint32_t status_code;
    const char *reason;

    xerrno = errno;

    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "REALPATH of '%s' blocked by <Limit> configuration", path);

    buf = fxb->ptr;
    buflen = fxb->bufsz;

    status_code = fxp_errno2status(xerrno, &reason);

    if (fxp_session->client_version <= 5 ||
        (fxp_session->client_version >= 6 &&
         realpath_flags != SSH2_FXRP_NO_CHECK)) {

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
        "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
        xerrno);

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        reason, NULL);

    } else {
      uint32_t attr_flags = 0;

      memset(&st, 0, sizeof(st));
      st.st_uid = (uid_t) -1;
      st.st_gid = (gid_t) -1;

      pr_trace_msg(trace_channel, 8, "sending response: NAME 1 %s %s",
        path, fxp_strattrs(fxp->pool, &st, &attr_flags));

      sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_NAME);
      sftp_msg_write_int(&buf, &buflen, fxp->request_id);
      sftp_msg_write_int(&buf, &buflen, 1);

      fxb->buf = buf;
      fxb->buflen = buflen;

      fxp_name_write(fxp->pool, fxb, path, &st, 0, "nobody", "nobody");

      buf = fxb->buf;
      buflen = fxb->buflen;
    }

    fxp_cmd_dispatch_err(cmd);

  } else {
   /* draft-ietf-secsh-filexfer-13 says:
    *
    *  SSH_FXP_REALPATH_NO_CHECK:
    *    NOT resolve symbolic links (thus use lstat(2))
    *
    *  SSH_FXP_REALPATH_STAT_IF:
    *    stat(2) the file, but if the stat(2) fails, do NOT fail the request,
    *    but send a NAME with type UNKNOWN.
    *
    *  SSH_FXP_REALPATH_STAT_ALWAYS:
    *   stat(2) the file, and return any error.
    */

    pr_fs_clear_cache2(path);
    switch (realpath_flags) {
      case SSH2_FXRP_NO_CHECK:
        res = pr_fsio_lstat(path, &st);
        xerrno = errno;
        break;

      case SSH2_FXRP_STAT_IF:
      case SSH2_FXRP_STAT_ALWAYS:
        res = pr_fsio_stat(path, &st);
        xerrno = errno;
        break;
    }

    if (res < 0) {
      uint32_t status_code;
      const char *reason;

      xerrno = errno;

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error checking '%s' for REALPATH: %s", path, strerror(xerrno));

      buf = fxb->ptr;
      buflen = fxb->bufsz;

      status_code = fxp_errno2status(xerrno, &reason);

      if (fxp_session->client_version <= 5 ||
          (fxp_session->client_version >= 6 &&
           realpath_flags == SSH2_FXRP_STAT_ALWAYS)) {

        pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
          "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
          xerrno);

        fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
          reason, NULL);

      } else {
        uint32_t attr_flags = 0;

        memset(&st, 0, sizeof(st));
        st.st_uid = (uid_t) -1;
        st.st_gid = (gid_t) -1;

        pr_trace_msg(trace_channel, 8, "sending response: NAME 1 %s %s",
          path, fxp_strattrs(fxp->pool, &st, &attr_flags));

        sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_NAME);
        sftp_msg_write_int(&buf, &buflen, fxp->request_id);
        sftp_msg_write_int(&buf, &buflen, 1);

        fxb->buf = buf;
        fxb->buflen = buflen;

        fxp_name_write(fxp->pool, fxb, path, &st, 0, "nobody", "nobody");

        buf = fxb->buf;
        buflen = fxb->buflen;
      }

      fxp_cmd_dispatch_err(cmd);

    } else {
      const char *fake_user = NULL, *fake_group = NULL;

      pr_trace_msg(trace_channel, 8, "sending response: NAME 1 %s %s",
        path, fxp_strattrs(fxp->pool, &st, NULL));

      sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_NAME);
      sftp_msg_write_int(&buf, &buflen, fxp->request_id);
      sftp_msg_write_int(&buf, &buflen, 1);

      fake_user = get_param_ptr(get_dir_ctxt(fxp->pool, path), "DirFakeUser",
        FALSE);
      if (fake_user != NULL &&
          strncmp(fake_user, "~", 2) == 0) {
        fake_user = session.user;
      }

      fake_group = get_param_ptr(get_dir_ctxt(fxp->pool, path), "DirFakeGroup",
        FALSE);
      if (fake_group != NULL &&
          strncmp(fake_group, "~", 2) == 0) {
        fake_group = session.group;
      }

      fxb->buf = buf;
      fxb->buflen = buflen;

      fxp_name_write(fxp->pool, fxb, path, &st, 0, fake_user, fake_group);

      buf = fxb->buf;
      buflen = fxb->buflen;

      fxp_cmd_dispatch(cmd);
    }
  }

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = fxb->ptr;
  resp->payload_sz = (fxb->bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_remove(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *cmd_name, *path, *real_path;
  const char *reason;
  uint32_t buflen, bufsz, status_code;
  struct stat st;
  struct fxp_packet *resp;
  cmd_rec *cmd, *cmd2;
  int res;

  path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    path = sftp_utf8_decode_str(fxp->pool, path);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "REMOVE", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", path, NULL, NULL);

  pr_proctitle_set("%s - %s: REMOVE %s", session.user, session.proc_prefix,
    path);

  pr_trace_msg(trace_channel, 7, "received request: REMOVE %s", path);

  if (strlen(path) == 0) {
    /* Use the default directory if the path is empty. */
    path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty path given in REMOVE request, using '%s'", path);
  }

  cmd = fxp_cmd_alloc(fxp->pool, "REMOVE", path);
  cmd->cmd_class = CL_WRITE|CL_SFTP;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "REMOVE of '%s' blocked by '%s' handler", path, (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  path = cmd->arg;

  cmd2 = fxp_cmd_alloc(fxp->pool, C_DELE, path);
  if (pr_cmd_dispatch_phase(cmd2, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "DELE of '%s' blocked by '%s' handler", path, (char *) cmd2->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", path, strerror(EPERM));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = cmd2->arg;

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, C_DELE);

  if (!dir_check_canon(fxp->pool, cmd, G_WRITE, path, NULL)) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    pr_cmd_set_name(cmd, cmd_name);

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "REMOVE of '%s' blocked by <Limit> configuration", path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", path, strerror(EPERM));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_cmd_set_name(cmd, cmd_name);

  if (fxp_path_pass_regex_filters(fxp->pool, "REMOVE", path) < 0) {
    int xerrno = errno;

    status_code = fxp_errno2status(errno, NULL);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", path, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  real_path = dir_canonical_path(fxp->pool, path);
  if (real_path == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error resolving '%s': %s", path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    pr_response_add_err(R_550, "%s: %s", path, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_fs_clear_cache2(real_path);
  res = pr_fsio_lstat(real_path, &st);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to check '%s': %s", real_path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    pr_response_add_err(R_550, "%s: %s", path, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (S_ISDIR(st.st_mode)) {
    int xerrno = EISDIR;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "unable to remove '%s': %s", real_path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    pr_response_add_err(R_550, "%s: %s", path, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  res = pr_fsio_unlink(real_path);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_trace_msg("fileperms", 1, "REMOVE, user '%s' (UID %s, GID %s): "
      "error deleting '%s': %s", session.user,
      pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
      real_path, strerror(xerrno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error unlinking '%s': %s", real_path, strerror(xerrno));

    pr_response_add_err(R_550, "%s: %s", path, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    errno = xerrno;

  } else {
    char *abs_path;

    /* The TransferLog format wants the full path to the deleted file,
     * regardless of a chroot.
     */
    abs_path = sftp_misc_vroot_abs_path(fxp->pool, path, TRUE);

    xferlog_write(0, session.c->remote_name, st.st_size, abs_path,
      'b', 'd', 'r', session.user, 'c', "_");

    pr_response_add(R_250, "%s command successful", (char *) cmd2->argv[0]);
    fxp_cmd_dispatch(cmd2);

    errno = 0;
  }

  status_code = fxp_errno2status(errno, &reason);

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
    "('%s' [%d])", (unsigned long) status_code, reason,
    errno != EOF ? strerror(errno) : "End of file", errno);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  if (res == 0) {
    fxp_cmd_dispatch(cmd);

  } else {
    fxp_cmd_dispatch_err(cmd);
  }

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_rename(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *args, *old_path, *new_path;
  const char *reason;
  uint32_t buflen, bufsz, flags, status_code;
  struct fxp_packet *resp;
  cmd_rec *cmd = NULL, *cmd2 = NULL, *cmd3 = NULL;
  int xerrno = 0;

  old_path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  new_path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);

  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    old_path = sftp_utf8_decode_str(fxp->pool, old_path);
    new_path = sftp_utf8_decode_str(fxp->pool, new_path);
  }

  /* In protocol version 5 and later, there is a flags int which follows.
   * However, this flags argument is usually used to indicate to servers
   * that they can use the POSIX rename(2) semantics, i.e. that overwriting
   * a file at the new/destination path is OK.
   *
   * At the moment, since we use rename(2) anyway, even for the older protocol
   * versions, we don't read in the flags value.  This does mean, however,
   * that mod_sftp will not properly return an "file already exists" error
   * if the specified new/destination path already exists.
   */

  args = pstrcat(fxp->pool, old_path, " ", new_path, NULL);

  pr_trace_msg(trace_channel, 7, "received request: RENAME %s %s", old_path,
    new_path);

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "RENAME", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", args, NULL, NULL);

  pr_proctitle_set("%s - %s: RENAME %s %s", session.user, session.proc_prefix,
    old_path, new_path);

  if (strlen(old_path) == 0) {
    /* Use the default directory if the path is empty. */
    old_path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty old path given in RENAME request, using '%s'", old_path);
  }

  if (strlen(new_path) == 0) {
    /* Use the default directory if the path is empty. */
    new_path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty new path given in RENAME request, using '%s'", new_path);
  }

  if (fxp_session->client_version > 4) {
    flags = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

    if (flags & SSH2_FXR_ATOMIC) {
      /* The ATOMIC flag implies OVERWRITE. */
      flags |= SSH2_FXR_OVERWRITE;
    }

  } else {
    flags = 0;
  }

  cmd = fxp_cmd_alloc(fxp->pool, "RENAME", args);
  cmd->cmd_class = CL_MISC|CL_SFTP;
 
  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  cmd2 = fxp_cmd_alloc(fxp->pool, C_RNFR, old_path);
  cmd2->cmd_class = CL_MISC|CL_WRITE;
  if (pr_cmd_dispatch_phase(cmd2, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RENAME from '%s' blocked by '%s' handler", old_path,
      (char *) cmd2->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  old_path = dir_best_path(fxp->pool, cmd2->arg);
  if (old_path == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RENAME request denied: unable to access path '%s'", cmd2->arg);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (pr_table_add(session.notes, "mod_core.rnfr-path",
      pstrdup(session.pool, old_path), 0) < 0) {
    if (errno != EEXIST) {
      pr_trace_msg(trace_channel, 8,
        "error setting 'mod_core.rnfr-path' note: %s", strerror(errno));
    }
  }

  cmd3 = fxp_cmd_alloc(fxp->pool, C_RNTO, new_path);
  cmd3->cmd_class = CL_MISC|CL_WRITE;
  if (pr_cmd_dispatch_phase(cmd3, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RENAME to '%s' blocked by '%s' handler", new_path,
      (char *) cmd3->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd3);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  new_path = dir_best_path(fxp->pool, cmd3->arg);
  if (new_path == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RENAME request denied: unable to access path '%s'", cmd3->arg);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd3);

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (!dir_check(fxp->pool, cmd2, G_DIRS, old_path, NULL) ||
      !dir_check(fxp->pool, cmd3, G_WRITE, new_path, NULL)) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RENAME of '%s' to '%s' blocked by <Limit> configuration",
      old_path, new_path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd3);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (strcmp(old_path, new_path) == 0) {
    xerrno = EEXIST;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RENAME of '%s' to same path '%s', rejecting", old_path, new_path);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
      xerrno);

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd3);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (!(flags & SSH2_FXR_OVERWRITE) &&
      exists2(fxp->pool, new_path)) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "denying RENAME of '%s' to '%s': '%s' already exists and client did not "
      "specify OVERWRITE flag", old_path, new_path, new_path);

    status_code = SSH2_FX_FILE_ALREADY_EXISTS;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd3);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxp_path_pass_regex_filters(fxp->pool, "RENAME", old_path) < 0 ||
      fxp_path_pass_regex_filters(fxp->pool, "RENAME", new_path) < 0) {
    xerrno = errno;

    status_code = fxp_errno2status(xerrno, NULL);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    pr_response_add_err(R_550, "%s: %s", cmd3->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd3);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (pr_fsio_rename(old_path, new_path) < 0) {
    if (errno != EXDEV) {
      xerrno = errno;

      (void) pr_trace_msg("fileperms", 1, "RENAME, user '%s' (UID %s, "
        "GID %s): error renaming '%s' to '%s': %s", session.user,
        pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
        old_path, new_path, strerror(xerrno));

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error renaming '%s' to '%s': %s", old_path, new_path,
        strerror(xerrno));

      errno = xerrno;

    } else {
      /* In this case, we should manually copy the file from the source
       * path to the destination path.
       */
      errno = 0;
      if (pr_fs_copy_file2(old_path, new_path, 0, NULL) < 0) {
        xerrno = errno;

        (void) pr_trace_msg("fileperms", 1, "RENAME, user '%s' (UID %s, "
          "GID %s): error copying '%s' to '%s': %s", session.user,
          pr_uid2str(fxp->pool, session.uid),
          pr_gid2str(fxp->pool, session.gid), old_path, new_path,
          strerror(xerrno));

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error copying '%s' to '%s': %s", old_path, new_path,
          strerror(xerrno));

        errno = xerrno;

      } else {
        /* Once copied, remove the original path. */
        if (pr_fsio_unlink(old_path) < 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "error deleting '%s': %s", old_path, strerror(errno));
        }

        xerrno = errno = 0;
      }
    }

  } else {
    /* No errors. */
    xerrno = errno = 0;
  }

  status_code = fxp_errno2status(xerrno, &reason);

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
    "('%s' [%d])", (unsigned long) status_code, reason,
    xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

  /* Clear out any transfer-specific data. */
  if (session.xfer.p) {
    destroy_pool(session.xfer.p);
  }
  memset(&session.xfer, 0, sizeof(session.xfer));

  /* The timing of these steps may look peculiar, but it's deliberate,
   * in order to get the expected log messages in an ExtendedLog.
   */

  session.xfer.p = make_sub_pool(fxp_pool);
  pr_pool_tag(session.xfer.p, "SFTP session transfer pool");
  memset(&session.xfer.start_time, 0, sizeof(session.xfer.start_time));
  gettimeofday(&session.xfer.start_time, NULL);

  session.xfer.path = pstrdup(session.xfer.p, old_path);

  if (xerrno == 0) {
    pr_response_add(R_350,
      "File or directory exists, ready for destination name");
    fxp_cmd_dispatch(cmd2);

  } else {
    pr_response_add_err(R_550, "%s: %s", (char *) cmd2->argv[0],
      strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);
  }

  session.xfer.path = pstrdup(session.xfer.p, new_path);

  if (xerrno == 0) {
    pr_response_add(R_250, "Rename successful");
    fxp_cmd_dispatch(cmd3);

  } else {
    pr_response_add_err(R_550, "%s: %s", (char *) cmd3->argv[0],
      strerror(xerrno));
    fxp_cmd_dispatch_err(cmd3);
  }

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);
  if (xerrno == 0) {
    fxp_cmd_dispatch(cmd);

  } else {
    fxp_cmd_dispatch_err(cmd);
  }

  /* Clear out any transfer-specific data. */
  if (session.xfer.p) {
    destroy_pool(session.xfer.p);
  }
  memset(&session.xfer, 0, sizeof(session.xfer));

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_rmdir(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *cmd_name, *path;
  const char *reason;
  uint32_t buflen, bufsz, status_code;
  struct fxp_packet *resp;
  cmd_rec *cmd, *cmd2;
  int have_error = FALSE, res = 0;
  struct stat st;

  path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    path = sftp_utf8_decode_str(fxp->pool, path);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "RMDIR", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", path, NULL, NULL);

  pr_proctitle_set("%s - %s: RMDIR %s", session.user, session.proc_prefix,
    path);

  pr_trace_msg(trace_channel, 7, "received request: RMDIR %s", path);

  if (strlen(path) == 0) {
    /* Use the default directory if the path is empty. */
    path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty path given in RMDIR request, using '%s'", path);
  }

  cmd = fxp_cmd_alloc(fxp->pool, "RMDIR", path);
  cmd->cmd_class = CL_WRITE|CL_SFTP;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RMDIR of '%s' blocked by '%s' handler", path, (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = cmd->arg;

  pr_fs_clear_cache2(path);
  if (pr_fsio_lstat(path, &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      char link_path[PR_TUNABLE_PATH_MAX];
      int len;

      memset(link_path, '\0', sizeof(link_path));
      len = dir_readlink(fxp->pool, path, link_path, sizeof(link_path)-1,
        PR_DIR_READLINK_FL_HANDLE_REL_PATH);
      if (len > 0) {
        link_path[len] = '\0';
        path = pstrdup(fxp->pool, link_path);
      }
    }
  }

  path = dir_best_path(fxp->pool, path);
  if (path == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RMDIR request denied: unable to access path '%s'", cmd->arg);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  cmd2 = fxp_cmd_alloc(fxp->pool, C_RMD, path);
  if (pr_cmd_dispatch_phase(cmd2, PRE_CMD, 0) == -1) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RMDIR of '%s' blocked by '%s' handler", path, (char *) cmd2->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = cmd2->arg;

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, C_RMD);

  if (!dir_check(fxp->pool, cmd, G_WRITE, path, NULL)) {
    have_error = TRUE;
  }

  pr_cmd_set_name(cmd, C_XRMD);

  if (!have_error &&
      !dir_check(fxp->pool, cmd, G_WRITE, path, NULL)) {
    have_error = TRUE;
  }

  pr_cmd_set_name(cmd, cmd_name);

  if (have_error) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "RMDIR of '%s' blocked by <Limit> configuration", path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxp_path_pass_regex_filters(fxp->pool, "RMDIR", path) < 0) {
    int xerrno = errno;

    status_code = fxp_errno2status(xerrno, NULL);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(xerrno));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  res = pr_fsio_rmdir(path);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_trace_msg("fileperms", 1, "RMDIR, user '%s' (UID %s, GID %s): "
      "error removing directory '%s': %s", session.user,
      pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
      path, strerror(xerrno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error removing directory '%s': %s", path, strerror(xerrno));

#if defined(ENOTEMPTY) && ENOTEMPTY != EEXIST
    status_code = fxp_errno2status(xerrno, &reason);

#else
    /* On AIX5, ENOTEMPTY and EEXIST are defined to the same value.  See:
     *
     *  http://forums.proftpd.org/smf/index.php/topic,3971.0.html
     *
     * We still want to send the proper SFTP error code/string if we see
     * these values, though.  The fix for handling this case in
     * fxp_errno2status() means that we need to do the errno lookup a little
     * more manually here.
     */

    if (xerrno != ENOTEMPTY) {
      status_code = fxp_errno2status(xerrno, &reason);

    } else {
      /* Generic failure code, works for all protocol versions. */
      status_code = SSH2_FX_FAILURE;

      if (fxp_session->client_version > 3) {
        status_code = SSH2_FX_FILE_ALREADY_EXISTS;
      }

      if (fxp_session->client_version > 5) {
        status_code = SSH2_FX_DIR_NOT_EMPTY;
      }

      reason = fxp_strerror(status_code);
    }
#endif

    errno = xerrno;

  } else {
    /* No error. */
    errno = 0;
    status_code = SSH2_FX_OK;
    reason = fxp_strerror(status_code);
  }

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
    "('%s' [%d])", (unsigned long) status_code, reason,
    errno != EOF ? strerror(errno) : "End of file", errno);

  if (res == 0) {
    fxp_cmd_dispatch(cmd2);

  } else {
    fxp_cmd_dispatch_err(cmd2);
  }

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  if (res == 0) {
    fxp_cmd_dispatch(cmd);

  } else {
    fxp_cmd_dispatch_err(cmd);
  }

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_setstat(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *attrs_str, *cmd_name, *path;
  const char *reason;
  uint32_t attr_flags, buflen, bufsz, status_code;
  int res;
  struct stat *attrs;
  struct fxp_packet *resp;
  cmd_rec *cmd;
  struct stat st;
  array_header *xattrs = NULL;

  path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    path = sftp_utf8_decode_str(fxp->pool, path);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "SETSTAT", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", path, NULL, NULL);

  attrs = fxp_attrs_read(fxp, &fxp->payload, &fxp->payload_sz, &attr_flags,
    &xattrs);
  if (attrs == NULL) {
    return 0;
  }

  attrs_str = fxp_strattrs(fxp->pool, attrs, &attr_flags);

  pr_proctitle_set("%s - %s: SETSTAT %s %s", session.user, session.proc_prefix,
    path, attrs_str);

  pr_trace_msg(trace_channel, 7, "received request: SETSTAT %s %s", path,
    attrs_str);

  if (strlen(path) == 0) {
    /* Use the default directory if the path is empty. */
    path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty path given in SETSTAT request, using '%s'", path);
  }

  cmd = fxp_cmd_alloc(fxp->pool, "SETSTAT", path);
  cmd->cmd_class = CL_WRITE|CL_SFTP;

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SETSTAT of '%s' blocked by '%s' handler", path, (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = cmd->arg;

  pr_fs_clear_cache2(path);
  if (pr_fsio_lstat(path, &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      char link_path[PR_TUNABLE_PATH_MAX];
      int len;

      memset(link_path, '\0', sizeof(link_path));
      len = dir_readlink(fxp->pool, path, link_path, sizeof(link_path)-1,
        PR_DIR_READLINK_FL_HANDLE_REL_PATH);
      if (len > 0) {
        link_path[len] = '\0';
        path = pstrdup(fxp->pool, link_path);
      }
    }
  }

  path = dir_best_path(fxp->pool, path);
  if (path == NULL) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SETSTAT request denied: unable to access path '%s'", cmd->arg);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "SETSTAT");

  if (!dir_check(fxp->pool, cmd, G_WRITE, path, NULL)) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    pr_cmd_set_name(cmd, cmd_name);

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SETSTAT of '%s' blocked by <Limit> configuration", path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }
  pr_cmd_set_name(cmd, cmd_name);

  attr_flags = fxp_attrs_clear_unsupported(attr_flags);

  /* If the SFTPOption for ignoring the owners for SFTP setstat requests is set,
   * handle it by clearing the SSH2_FX_ATTR_UIDGID and SSH2_FX_ATTR_OWNERGROUP
   * flags.
   */
  if ((sftp_opts & SFTP_OPT_IGNORE_SFTP_SET_OWNERS) &&
      ((attr_flags & SSH2_FX_ATTR_UIDGID) ||
       (attr_flags & SSH2_FX_ATTR_OWNERGROUP))) {
    pr_trace_msg(trace_channel, 7, "SFTPOption 'IgnoreSFTPSetOwners' "
      "configured, ignoring ownership sent by client");
    attr_flags &= ~SSH2_FX_ATTR_UIDGID;
    attr_flags &= ~SSH2_FX_ATTR_OWNERGROUP;
  }

  /* If the SFTPOption for ignoring the xattrs for SFTP setstat requests is set,
   * handle it by clearing the SSH2_FX_ATTR_EXTENDED flag.
   */
  if ((sftp_opts & SFTP_OPT_IGNORE_SFTP_SET_XATTRS) &&
      (attr_flags & SSH2_FX_ATTR_EXTENDED)) {
    pr_trace_msg(trace_channel, 7,
      "SFTPOption 'IgnoreSFTPSetExtendedAttributes' configured, ignoring "
      "xattrs sent by client");
    attr_flags &= ~SSH2_FX_ATTR_EXTENDED;
  }

  /* If the SFTPOption for ignoring the perms for SFTP setstat requests is set,
   * handle it by clearing the SSH2_FX_ATTR_PERMISSIONS flag.
   */
  if ((sftp_opts & SFTP_OPT_IGNORE_SFTP_SET_PERMS) &&
      (attr_flags & SSH2_FX_ATTR_PERMISSIONS)) {
    pr_trace_msg(trace_channel, 7, "SFTPOption 'IgnoreSFTPSetPerms' "
      "configured, ignoring perms sent by client");
    attr_flags &= ~SSH2_FX_ATTR_PERMISSIONS;
  }

  /* If the SFTPOption for ignoring the times for SFTP setstat requests is set,
   * handle it by clearing the time-related SSH2_FX_ATTR flags.
   */
  if (sftp_opts & SFTP_OPT_IGNORE_SFTP_SET_TIMES) {
    if ((attr_flags & SSH2_FX_ATTR_ACCESSTIME) ||
        (attr_flags & SSH2_FX_ATTR_MODIFYTIME)) {
      pr_trace_msg(trace_channel, 7, "SFTPOption 'IgnoreSFTPSetTimes' "
        "configured, ignoring times sent by client");
      attr_flags &= ~SSH2_FX_ATTR_ACCESSTIME;
      attr_flags &= ~SSH2_FX_ATTR_MODIFYTIME;
    }
  }

  res = fxp_attrs_set(NULL, path, attrs, attr_flags, xattrs, &buf, &buflen,
    fxp);
  if (res < 0) {
    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  status_code = fxp_errno2status(0, &reason);

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, reason);

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_stat(struct fxp_packet *fxp) {
  unsigned char *buf;
  char *cmd_name, *path;
  uint32_t attr_flags, buflen;
  struct stat st;
  struct fxp_buffer *fxb;
  struct fxp_packet *resp;
  cmd_rec *cmd;
  const char *fake_user = NULL, *fake_group = NULL;

  path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    path = sftp_utf8_decode_str(fxp->pool, path);
  }

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "STAT", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", path, NULL, NULL);

  pr_proctitle_set("%s - %s: STAT %s", session.user, session.proc_prefix, path);

  if (fxp_session->client_version > 3) {
    attr_flags = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

    pr_trace_msg(trace_channel, 7, "received request: STAT %s %s", path,
      fxp_strattrflags(fxp->pool, attr_flags));

  } else {
    pr_trace_msg(trace_channel, 7, "received request: STAT %s", path);
    attr_flags = SSH2_FX_ATTR_SIZE|SSH2_FX_ATTR_UIDGID|SSH2_FX_ATTR_PERMISSIONS|
      SSH2_FX_ATTR_ACMODTIME;
#ifdef PR_USE_XATTR
    if (!(fxp_fsio_opts & PR_FSIO_OPT_IGNORE_XATTR)) {
      attr_flags |= SSH2_FX_ATTR_EXTENDED;
    }
#endif /* PR_USE_XATTR */
  }

  if (strlen(path) == 0) {
    /* Use the default directory if the path is empty. */
    path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty path given in STAT request, using '%s'", path);
  }

  cmd = fxp_cmd_alloc(fxp->pool, "STAT", path);
  cmd->cmd_class = CL_READ|CL_SFTP;

  fxb = pcalloc(fxp->pool, sizeof(struct fxp_buffer));
  fxb->bufsz = buflen = FXP_RESPONSE_NAME_DEFAULT_SZ;
  fxb->ptr = buf = palloc(fxp->pool, fxb->bufsz);

  if (pr_cmd_dispatch_phase(cmd, PRE_CMD, 0) < 0) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "STAT of '%s' blocked by '%s' handler", path, (char *) cmd->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The path may have been changed by any PRE_CMD handlers. */
  path = cmd->arg;

  pr_fs_clear_cache2(path);
  if (pr_fsio_lstat(path, &st) == 0) {
    if (S_ISLNK(st.st_mode)) {
      char link_path[PR_TUNABLE_PATH_MAX];
      int len;

      memset(link_path, '\0', sizeof(link_path));
      len = dir_readlink(fxp->pool, path, link_path, sizeof(link_path)-1,
        PR_DIR_READLINK_FL_HANDLE_REL_PATH);
      if (len > 0) {
        link_path[len] = '\0';
        path = pstrdup(fxp->pool, link_path);
      }
    }
  }

  path = dir_best_path(fxp->pool, path);
  if (path == NULL) {
    int xerrno = EACCES;
    const char *reason;
    uint32_t status_code;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "STAT request denied: unable to access path '%s'", cmd->arg);

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(xerrno),
       xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "STAT");

  if (!dir_check(fxp->pool, cmd, G_READ, path, NULL)) {
    uint32_t status_code = SSH2_FX_PERMISSION_DENIED;

    pr_cmd_set_name(cmd, cmd_name);

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "STAT of '%s' blocked by <Limit> configuration", path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }
  pr_cmd_set_name(cmd, cmd_name);

  pr_fs_clear_cache2(path);
  if (pr_fsio_stat(path, &st) < 0) {
    uint32_t status_code;
    const char *reason;
    int xerrno = errno;

    if (xerrno != ENOENT) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error checking '%s' for STAT: %s", path, strerror(xerrno));
    }

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = fxb->ptr;
    resp->payload_sz = (fxb->bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg(trace_channel, 8, "sending response: ATTRS %s",
    fxp_strattrs(fxp->pool, &st, &attr_flags));

  sftp_msg_write_byte(&buf, &buflen, SFTP_SSH2_FXP_ATTRS);
  sftp_msg_write_int(&buf, &buflen, fxp->request_id);

  fake_user = get_param_ptr(get_dir_ctxt(fxp->pool, path), "DirFakeUser",
    FALSE);
  if (fake_user != NULL &&
      strncmp(fake_user, "~", 2) == 0) {
    fake_user = session.user;
  }

  fake_group = get_param_ptr(get_dir_ctxt(fxp->pool, path), "DirFakeGroup",
    FALSE);
  if (fake_group != NULL &&
      strncmp(fake_group, "~", 2) == 0) {
    fake_group = session.group;
  }

  fxb->buf = buf;
  fxb->buflen = buflen;

  attr_flags = fxp_attrs_clear_unsupported(attr_flags);
  if (fxp_session->client_version > 3 &&
      sftp_opts & SFTP_OPT_INCLUDE_SFTP_TIMES) {
    pr_trace_msg(trace_channel, 17,
      "SFTPOption IncludeSFTPTimes in effect; assuring presence of "
      "ACCESSTIME/MODIFYTIME attributes");
    attr_flags |= SSH2_FX_ATTR_ACCESSTIME;
    attr_flags |= SSH2_FX_ATTR_MODIFYTIME;
  }

  fxp_attrs_write(fxp->pool, fxb, path, &st, attr_flags, fake_user, fake_group);

  buf = fxb->buf;
  buflen = fxb->buflen;

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = fxb->ptr;
  resp->payload_sz = (fxb->bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_symlink(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *args, *args2, *cmd_name, *link_path, *link_vpath, *target_path,
    *target_vpath, *vpath;
  const char *reason;
  int have_error = FALSE, res;
  uint32_t buflen, bufsz, status_code;
  struct fxp_packet *resp;
  cmd_rec *cmd, *cmd2;

  /* Note: The ietf-secsh-filexfer drafts define the arguments for SYMLINK
   * as "linkpath" (the file being created), followed by "targetpath" (the
   * target of the link).  The following code reads the arguments in the
   * opposite (thus wrong) order.  This is done deliberately, to match
   * the behavior that OpenSSH uses; see:
   *
   *  https://bugzilla.mindrot.org/show_bug.cgi?id=861
   */

  target_path = sftp_msg_read_string(fxp->pool, &fxp->payload,
    &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    target_path = sftp_utf8_decode_str(fxp->pool, target_path);
  }

  link_path = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  if (fxp_session->client_version >= fxp_utf8_protocol_version) {
    link_path = sftp_utf8_decode_str(fxp->pool, link_path);
  }

  args = pstrcat(fxp->pool, target_path, " ", link_path, NULL);

  cmd = fxp_cmd_alloc(fxp->pool, "SYMLINK", args);
  cmd->cmd_class = CL_WRITE|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "SYMLINK", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", args, NULL, NULL);

  pr_proctitle_set("%s - %s: SYMLINK %s %s", session.user, session.proc_prefix,
    link_path, target_path);

  pr_trace_msg(trace_channel, 7, "received request: SYMLINK %s %s", target_path,
    link_path);

  if (strlen(target_path) == 0) {
    /* Use the default directory if the path is empty. */
    target_path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty target path given in SYMLINK request, using '%s'", target_path);
  }

  if (strlen(link_path) == 0) {
    /* Use the default directory if the path is empty. */
    link_path = sftp_auth_get_default_dir();

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "empty link path given in SYMLINK request, using '%s'", link_path);
  }

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  /* Make sure we use the full paths. */
  vpath = dir_canonical_vpath(fxp->pool, target_path);
  if (vpath == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error resolving '%s': %s", target_path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }
  target_vpath = vpath;

  vpath = dir_canonical_vpath(fxp->pool, link_path);
  if (vpath == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error resolving '%s': %s", link_path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }
  link_vpath = vpath;

  /* We use a slightly different cmd_rec here, for the benefit of PRE_CMD
   * handlers such as mod_rewrite.  It is impossible for a client to
   * send a tab ('\t') in SFTP, so we use that as our delimiter in the
   * single-string args argument in the cmd_rec.
   *
   * If the PRE_CMD dispatch is successful, we can then check to see
   * if the args string changed, and if so, parse back out the individual
   * paths.
   */

  args2 = pstrcat(fxp->pool, target_vpath, "\t", link_vpath, NULL);
  cmd2 = fxp_cmd_alloc(fxp->pool, "SYMLINK", args2);
  cmd2->cmd_class = CL_WRITE;

  if (pr_cmd_dispatch_phase(cmd2, PRE_CMD, 0) < 0) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SYMLINK of '%s' to '%s' blocked by '%s' handler", target_path, link_path,
      (char *) cmd2->argv[0]);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    pr_response_add_err(R_550, "%s: %s", cmd2->arg, strerror(EACCES));
    fxp_cmd_dispatch_err(cmd2);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  /* The paths may have been changed by any PRE_CMD handlers. */
  if (strcmp(args2, cmd2->arg) != 0) {
    char *ptr2;

    ptr2 = strchr(cmd2->arg, '\t');
    if (ptr2) {
      *ptr2 = '\0';
      target_path = cmd2->arg;
      link_path = ptr2 + 1;
    }
  }

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "SYMLINK");

  if (!dir_check(fxp->pool, cmd, G_READ, target_vpath, NULL)) {
    pr_cmd_set_name(cmd, cmd_name);
    have_error = TRUE;
  }

  if (!have_error &&
      !dir_check(fxp->pool, cmd, G_WRITE, link_vpath, NULL)) {
    pr_cmd_set_name(cmd, cmd_name);
    have_error = TRUE;
  }

  pr_cmd_set_name(cmd, cmd_name);

  if (have_error) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "SYMLINK of '%s' to '%s' blocked by <Limit> configuration",
      target_path, link_path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  res = pr_fsio_symlink(target_path, link_path);

  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error symlinking '%s' to '%s': %s", target_path, link_path,
      strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_cmd_dispatch_err(cmd);

  } else {
    errno = 0;
    status_code = fxp_errno2status(0, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, reason);

    fxp_cmd_dispatch(cmd);
  }

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    reason, NULL);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_write(struct fxp_packet *fxp) {
  unsigned char *buf, *data, *ptr;
  char cmd_arg[256], *file, *name, *ptr2;
  int res, xerrno = 0;
  uint32_t buflen, bufsz, datalen, status_code;
  uint64_t offset;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  cmd_rec *cmd, *cmd2;
  pr_buffer_t *pbuf;

  name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  offset = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);
  datalen = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);
  data = sftp_msg_read_data(fxp->pool, &fxp->payload, &fxp->payload_sz,
    datalen);

  memset(cmd_arg, '\0', sizeof(cmd_arg)); 
  pr_snprintf(cmd_arg, sizeof(cmd_arg)-1, "%s %" PR_LU " %lu", name,
    (pr_off_t) offset, (unsigned long) datalen);
  cmd = fxp_cmd_alloc(fxp->pool, "WRITE", cmd_arg);
  cmd->cmd_class = CL_WRITE|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "WRITE", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", name, NULL, NULL);

  pr_proctitle_set("%s - %s: WRITE %s %" PR_LU " %lu", session.user,
    session.proc_prefix, name, (pr_off_t) offset, (unsigned long) datalen);

  pr_trace_msg(trace_channel, 7, "received request: WRITE %s %" PR_LU " %lu",
    name, (pr_off_t) offset, (unsigned long) datalen);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  fxh = fxp_handle_get(name);
  if (fxh == NULL) {
    pr_trace_msg(trace_channel, 17,
      "%s: unable to find handle for name '%s': %s", (char *) cmd->argv[0],
      name, strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->fh == NULL) {
    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  /* Add a note containing the file handle for logging (Bug#3707). */
  fxp_set_filehandle_note(cmd, fxh);

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", fxh->fh->fh_path, NULL, NULL);
  fxh->fh_bytes_xferred += datalen;

  /* It would be nice to check the requested offset against the size of
   * the file.  However, the protocol specifically allows for sparse files,
   * where the requested offset is far beyond the end of the file.
   *
   * XXX Perhaps this should be configurable?
   */
#if 0
  if (offset > st.st_size) {
    const char *reason;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "requested write offset (%" PR_LU " bytes) greater than size of "
      "'%s' (%" PR_LU " bytes)", (pr_off_t) offset, fxh->fh->fh_path,
      (pr_off_t) st.st_size);

    status_code = fxp_errno2status(EINVAL, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason, strerror(EINVAL),
      EINVAL);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);
  
    return fxp_packet_write(resp);
  }
#endif

  /* Trim the full path to just the filename, for our STOR command. */
  ptr2 = strrchr(fxh->fh->fh_path, '/');
  if (ptr2 != NULL &&
      ptr2 != fxh->fh->fh_path) {
    file = pstrdup(fxp->pool, ptr2 + 1);

  } else {
    file = fxh->fh->fh_path;
  }

  cmd2 = fxp_cmd_alloc(fxp->pool, C_STOR, file);
  cmd2->cmd_class = CL_WRITE|CL_SFTP;

  if (!dir_check(fxp->pool, cmd2, G_WRITE, fxh->fh->fh_path, NULL)) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "WRITE of '%s' blocked by <Limit> configuration", fxh->fh->fh_path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxp_path_pass_regex_filters(fxp->pool, "WRITE", fxh->fh->fh_path) < 0) {
    status_code = fxp_errno2status(errno, NULL);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (S_ISREG(fxh->fh_st->st_mode)) {
    if (pr_fsio_lseek(fxh->fh, offset, SEEK_SET) < 0) {
      const char *reason;
      xerrno = errno;

      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "error seeking to offset (%" PR_LU " bytes) for '%s': %s",
        (pr_off_t) offset, fxh->fh->fh_path, strerror(xerrno));

      status_code = fxp_errno2status(xerrno, &reason);

      pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
        "('%s' [%d])", (unsigned long) status_code, reason,
        xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

      fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
        reason, NULL);

      fxp_cmd_dispatch_err(cmd);

      resp = fxp_packet_create(fxp->pool, fxp->channel_id);
      resp->payload = ptr;
      resp->payload_sz = (bufsz - buflen);
  
      return fxp_packet_write(resp);

    } else {
      off_t *file_offset;

      /* Stash the offset at which we're writing to this file. */
      file_offset = palloc(cmd->pool, sizeof(off_t));
      *file_offset = (off_t) offset;
      (void) pr_table_add(cmd->notes, "mod_xfer.file-offset", file_offset,
        sizeof(off_t));
    }
  }

  /* If the open flags have O_APPEND, treat this as an APPE command, rather
   * than a STOR command.
   */
  if (!(fxh->fh_flags & O_APPEND)) {
    cmd2 = fxp_cmd_alloc(fxp->pool, C_STOR, NULL);

  } else {
    cmd2 = fxp_cmd_alloc(fxp->pool, C_APPE, NULL);
  }

  pbuf = pcalloc(fxp->pool, sizeof(pr_buffer_t));
  pbuf->buf = (char *) data;
  pbuf->buflen = datalen;
  pbuf->current = pbuf->buf;
  pbuf->remaining = 0;
  pr_event_generate("mod_sftp.sftp.data-read", pbuf);

  pr_throttle_init(cmd2);
  
  res = pr_fsio_write(fxh->fh, (char *) data, datalen);
  xerrno = errno;

  /* Increment the "on-disk" file size with the number of bytes written.
   * We do this, rather than using fstat(2), to avoid performance penalties
   * associated with fstat(2) on network filesystems such as NFS.  And we
   * want to track the on-disk size for enforcing limits such as
   * MaxStoreFileSize.
   *
   * Note that we only want to increment the file size if the chunk we
   * just wrote is PAST the current end of the file; we could be just
   * overwriting a chunk of the file.
   */
  if (res > 0) {
    size_t new_size;

    new_size = offset + res;
    if ((off_t) new_size > fxh->fh_st->st_size) {
      fxh->fh_st->st_size = new_size;
    }

    session.xfer.total_bytes += datalen;
    session.total_bytes += datalen;
  }

  if (pr_data_get_timeout(PR_DATA_TIMEOUT_NO_TRANSFER) > 0) {
    pr_timer_reset(PR_TIMER_NOXFER, ANY_MODULE);
  }

  if (pr_data_get_timeout(PR_DATA_TIMEOUT_STALLED) > 0) {
    pr_timer_reset(PR_TIMER_STALLED, ANY_MODULE);
  }

  pr_throttle_pause(offset, FALSE);

  if (res < 0) {
    const char *reason;

    (void) pr_trace_msg("fileperms", 1, "WRITE, user '%s' (UID %s, GID %s): "
      "error writing to '%s': %s", session.user,
      pr_uid2str(fxp->pool, session.uid), pr_gid2str(fxp->pool, session.gid),
      fxh->fh->fh_path, strerror(xerrno));

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "error writing to '%s': %s", fxh->fh->fh_path, strerror(xerrno));

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->fh_st->st_size > 0) {
    config_rec *c;
    off_t nbytes_max_store = 0;

    /* Check MaxStoreFileSize */
    c = find_config(get_dir_ctxt(fxp->pool, fxh->fh->fh_path), CONF_PARAM,
      "MaxStoreFileSize", FALSE);
    if (c != NULL) {
      nbytes_max_store = *((off_t *) c->argv[0]);
    }

    if (nbytes_max_store > 0) {
      if (fxh->fh_st->st_size > nbytes_max_store) {
        const char *reason;
#if defined(EFBIG)
        xerrno = EFBIG;
#elif defined(ENOSPC)
        xerrno = ENOSPC;
#else
        xerrno = EIO;
#endif

        pr_log_pri(PR_LOG_NOTICE, "MaxStoreFileSize (%" PR_LU " %s) reached: "
          "aborting transfer of '%s'", (pr_off_t) nbytes_max_store,
          nbytes_max_store != 1 ? "bytes" : "byte", fxh->fh->fh_path);

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "error writing %" PR_LU " bytes to '%s': %s "
          "(MaxStoreFileSize %" PR_LU " exceeded)", (pr_off_t) datalen,
          fxh->fh->fh_path, strerror(xerrno), (pr_off_t) nbytes_max_store);

        status_code = fxp_errno2status(xerrno, &reason);

        pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
          "('%s' [%d])", (unsigned long) status_code, reason,
          strerror(xerrno), xerrno);

        fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
          reason, NULL);

        fxp_cmd_dispatch_err(cmd);

        resp = fxp_packet_create(fxp->pool, fxp->channel_id);
        resp->payload = ptr;
        resp->payload_sz = (bufsz - buflen);

        return fxp_packet_write(resp);
      }
    }
  }

  status_code = SSH2_FX_OK;

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, fxp_strerror(status_code));

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    fxp_strerror(status_code), NULL);

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_handle_unlock(struct fxp_packet *fxp) {
  unsigned char *buf, *ptr;
  char *cmd_name, *name;
  uint32_t buflen, bufsz, lock_flags, status_code;
  uint64_t offset, lock_len;
  struct flock lock;
  struct fxp_handle *fxh;
  struct fxp_packet *resp;
  cmd_rec *cmd;
  
  name = sftp_msg_read_string(fxp->pool, &fxp->payload, &fxp->payload_sz);
  offset = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);
  lock_len = sftp_msg_read_long(fxp->pool, &fxp->payload, &fxp->payload_sz);
  lock_flags = sftp_msg_read_int(fxp->pool, &fxp->payload, &fxp->payload_sz);

  cmd = fxp_cmd_alloc(fxp->pool, "UNLOCK", name);
  cmd->cmd_class = CL_WRITE|CL_SFTP;

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD, "%s", "UNLOCK", NULL, NULL);
  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", name, NULL, NULL);

  pr_proctitle_set("%s - %s: UNLOCK %s", session.user, session.proc_prefix,
    name);

  pr_trace_msg(trace_channel, 7,
    "received request: UNLOCK %s %" PR_LU " %" PR_LU " %lu", name,
    (pr_off_t) offset, (pr_off_t) lock_len, (unsigned long) lock_flags);

  buflen = bufsz = FXP_RESPONSE_DATA_DEFAULT_SZ;
  buf = ptr = palloc(fxp->pool, bufsz);

  fxh = fxp_handle_get(name);
  if (fxh == NULL) {
    pr_trace_msg(trace_channel, 17,
      "%s: unable to find handle for name '%s': %s", (char *) cmd->argv[0],
      name, strerror(errno));

    status_code = SSH2_FX_INVALID_HANDLE;

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  if (fxh->fh == NULL) {
    /* We do not support locking of directory handles, only files. */
    status_code = SSH2_FX_OP_UNSUPPORTED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested unsupported UNLOCK of a directory, rejecting");

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  cmd_name = cmd->argv[0];
  pr_cmd_set_name(cmd, "LOCK");

  if (!dir_check(fxp->pool, cmd, G_WRITE, fxh->fh->fh_path, NULL)) {
    status_code = SSH2_FX_PERMISSION_DENIED;

    pr_cmd_set_name(cmd, cmd_name);

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "UNLOCK of '%s' blocked by <Limit> configuration", fxh->fh->fh_path);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }
  pr_cmd_set_name(cmd, cmd_name);

  pr_scoreboard_entry_update(session.pid,
    PR_SCORE_CMD_ARG, "%s", fxh->fh->fh_path, NULL, NULL);

  if (lock_flags & SSH2_FXL_DELETE) {
    lock.l_type = F_UNLCK;

  } else {
    /* The LOCK command is used for adding locks, not UNLOCK. */
    status_code = SSH2_FX_OP_UNSUPPORTED;

    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested locking using UNLOCK, rejecting");

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
      (unsigned long) status_code, fxp_strerror(status_code));

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      fxp_strerror(status_code), NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);
  
    return fxp_packet_write(resp);
  }

  lock.l_whence = SEEK_SET;
  lock.l_start = offset;
  lock.l_len = lock_len;

  if (lock_len > 0) {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested unlocking of '%s' from %" PR_LU " for %" PR_LU
      " bytes", fxh->fh->fh_path, (pr_off_t) offset, (pr_off_t) lock_len);

  } else {
    (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
      "client requested unlocking of '%s' from %" PR_LU " to end-of-file",
      fxh->fh->fh_path, (pr_off_t) offset);
  }

  pr_trace_msg("lock", 9, "attempting to unlock file '%s'", fxh->fh->fh_path);

  while (fcntl(fxh->fh->fh_fd, F_SETLK, &lock) < 0) {
    int xerrno;
    const char *reason;

    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    xerrno = errno;
    pr_trace_msg("lock", 3, "unlock of '%s' failed: %s", fxh->fh->fh_path,
      strerror(errno)); 

    status_code = fxp_errno2status(xerrno, &reason);

    pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s' "
      "('%s' [%d])", (unsigned long) status_code, reason,
      xerrno != EOF ? strerror(xerrno) : "End of file", xerrno);

    fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
      reason, NULL);

    fxp_cmd_dispatch_err(cmd);

    resp = fxp_packet_create(fxp->pool, fxp->channel_id);
    resp->payload = ptr;
    resp->payload_sz = (bufsz - buflen);

    return fxp_packet_write(resp);
  }

  pr_trace_msg("lock", 9, "unlock of file '%s' successful", fxh->fh->fh_path);

  status_code = SSH2_FX_OK;

  pr_trace_msg(trace_channel, 8, "sending response: STATUS %lu '%s'",
    (unsigned long) status_code, fxp_strerror(status_code));

  fxp_status_write(fxp->pool, &buf, &buflen, fxp->request_id, status_code,
    fxp_strerror(status_code), NULL);

  fxp_cmd_dispatch(cmd);

  resp = fxp_packet_create(fxp->pool, fxp->channel_id);
  resp->payload = ptr;
  resp->payload_sz = (bufsz - buflen);

  return fxp_packet_write(resp);
}

static int fxp_send_display_login_file(uint32_t channel_id) {
  const char *msg;
  int res, xerrno;
  pool *sub_pool;

  if (fxp_sent_display_login_file) {
    /* Already sent the file; no need to do it again. */
    return 0;
  }

  if (fxp_displaylogin_fh == NULL) {
    /* No DisplayLogin file found. */
    return 0;
  }

  if (fxp_pool == NULL) {
    fxp_pool = make_sub_pool(sftp_pool);
    pr_pool_tag(fxp_pool, "SFTP Pool");
  }

  sub_pool = make_sub_pool(fxp_pool);
  pr_pool_tag(sub_pool, "SFTP DisplayLogin pool");

  msg = sftp_display_fh_get_msg(sub_pool, fxp_displaylogin_fh);
  pr_fsio_close(fxp_displaylogin_fh);

  if (msg == NULL) {
    destroy_pool(sub_pool);
    fxp_displaylogin_fh = NULL;
    return -1;
  }

  pr_trace_msg(trace_channel, 3,
    "sending data from DisplayLogin file '%s'", fxp_displaylogin_fh->fh_path);
  fxp_displaylogin_fh = NULL;

  res = sftp_channel_write_ext_data_stderr(sub_pool, channel_id,
    (unsigned char *) msg, strlen(msg));
  xerrno = errno;

  if (res == 0) {
    fxp_sent_display_login_file = TRUE;
  }

  destroy_pool(sub_pool);
  errno = xerrno;
  return res;
}

/* Main entry point */
int sftp_fxp_handle_packet(pool *p, void *ssh2, uint32_t channel_id,
    unsigned char *data, uint32_t datalen) {
  struct fxp_packet *fxp;
  int have_cache, res;

  /* Unused parameter; we read the SFTP request out of the provided buffer. */
  (void) ssh2;

  if (fxp_pool == NULL) {
    fxp_pool = make_sub_pool(sftp_pool);
    pr_pool_tag(fxp_pool, "SFTP Pool");
  }

  fxp = fxp_packet_read(channel_id, &data, &datalen, &have_cache);
  while (fxp) {
    pr_signals_handle();

    /* This is a bit of a hack, for playing along better with mod_vroot,
     * which pays attention to the session.curr_phase value.
     *
     * I'm not sure which is better here, PRE_CMD vs CMD.  Let's go with
     * PRE_CMD for now.
     */
    session.curr_phase = PRE_CMD;

    if (fxp->request_id) {
      pr_trace_msg(trace_channel, 6,
        "received %s (%d) SFTP request (request ID %lu, channel ID %lu)",
        fxp_get_request_type_desc(fxp->request_type), fxp->request_type,
        (unsigned long) fxp->request_id, (unsigned long) channel_id);

    } else {
      pr_trace_msg(trace_channel, 6,
        "received %s (%d) SFTP request (channel ID %lu)",
        fxp_get_request_type_desc(fxp->request_type), fxp->request_type,
        (unsigned long) channel_id);
    }

    if (fxp->packet_len > FXP_MAX_PACKET_LEN) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "received excessive SFTP packet (len %lu > max %lu bytes), rejecting",
        (unsigned long) fxp->packet_len, (unsigned long) FXP_MAX_PACKET_LEN);
      destroy_pool(fxp->pool);
      errno = EPERM;
      return -1;
    }

    fxp_session = fxp_get_session(channel_id);
    if (fxp_session == NULL) {
      (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
        "no existing SFTP session for channel ID %lu, rejecting request",
        (unsigned long) channel_id);
      destroy_pool(fxp->pool);
      errno = EPERM;
      return -1;
    }

    pr_response_set_pool(fxp->pool);

    /* Make sure to clear the response lists of any cruft from previous
     * requests.
     */
    pr_response_clear(&resp_list);
    pr_response_clear(&resp_err_list);

    switch (fxp->request_type) {
      case SFTP_SSH2_FXP_INIT:
        /* If we already know the version, then the client has sent
         * FXP_INIT before, and should NOT be sending it again.
         *
         * However, per Bug#4227, there ARE clients which do send INIT
         * multiple times; I don't know why.  And since OpenSSH handles
         * these repeated INITs without disconnecting clients, that is the
         * de facto expected behavior.  We will do the same, but at least
         * log about it.
         */
        if (fxp_session->client_version > 0) {
          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "already received SFTP INIT %u request from client",
            (unsigned int) fxp_session->client_version);
        }

        res = fxp_handle_init(fxp);
        break;

      case SFTP_SSH2_FXP_CLOSE:
        allow_version_select = FALSE;
        res = fxp_handle_close(fxp);
        break;

      case SFTP_SSH2_FXP_EXTENDED:
        res = fxp_handle_extended(fxp);
        break;

      case SFTP_SSH2_FXP_FSETSTAT:
        allow_version_select = FALSE;
        res = fxp_handle_fsetstat(fxp);
        break;

      case SFTP_SSH2_FXP_FSTAT:
        allow_version_select = FALSE;
        res = fxp_handle_fstat(fxp);
        break;

      case SFTP_SSH2_FXP_LINK:
        allow_version_select = FALSE;
        res = fxp_handle_link(fxp);
        break;

      case SFTP_SSH2_FXP_LOCK:
        allow_version_select = FALSE;
        res = fxp_handle_lock(fxp);
        break;

      case SFTP_SSH2_FXP_LSTAT:
        allow_version_select = FALSE;
        res = fxp_handle_lstat(fxp);
        break;

      case SFTP_SSH2_FXP_MKDIR:
        allow_version_select = FALSE;
        res = fxp_handle_mkdir(fxp);
        break;

      case SFTP_SSH2_FXP_OPEN:
        allow_version_select = FALSE;
        res = fxp_handle_open(fxp);
        break;

      case SFTP_SSH2_FXP_OPENDIR:
        allow_version_select = FALSE;
        res = fxp_handle_opendir(fxp);
        break;

      case SFTP_SSH2_FXP_READ:
        allow_version_select = FALSE;
        res = fxp_handle_read(fxp);
        break;

      case SFTP_SSH2_FXP_READDIR:
        allow_version_select = FALSE;
        res = fxp_handle_readdir(fxp);
        break;

      case SFTP_SSH2_FXP_READLINK:
        allow_version_select = FALSE;
        res = fxp_handle_readlink(fxp);
        break;

      case SFTP_SSH2_FXP_REALPATH:
        allow_version_select = FALSE;
        res = fxp_handle_realpath(fxp);
        break;

      case SFTP_SSH2_FXP_REMOVE:
        allow_version_select = FALSE;
        res = fxp_handle_remove(fxp);
        break;

      case SFTP_SSH2_FXP_RENAME:
        allow_version_select = FALSE;
        res = fxp_handle_rename(fxp);
        break;

      case SFTP_SSH2_FXP_RMDIR:
        allow_version_select = FALSE;
        res = fxp_handle_rmdir(fxp);
        break;

      case SFTP_SSH2_FXP_SETSTAT:
        allow_version_select = FALSE;
        res = fxp_handle_setstat(fxp);
        break;

      case SFTP_SSH2_FXP_STAT:
        allow_version_select = FALSE;
        res = fxp_handle_stat(fxp);
        break;

      case SFTP_SSH2_FXP_SYMLINK:
        allow_version_select = FALSE;
        res = fxp_handle_symlink(fxp);
        break;

      case SFTP_SSH2_FXP_WRITE:
        allow_version_select = FALSE;
        res = fxp_handle_write(fxp);
        break;

      case SFTP_SSH2_FXP_UNLOCK:
        allow_version_select = FALSE;
        res = fxp_handle_unlock(fxp);
        break;

      default:
        pr_event_generate("sftp.invalid-request", fxp);

        (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
          "unhandled SFTP request type %d", fxp->request_type);
        destroy_pool(fxp->pool);
        fxp_packet_set_packet(NULL);
        fxp_session = NULL;
        return -1;
    }

    destroy_pool(fxp->pool);
    fxp_packet_set_packet(NULL);

    if (res < 0) {
      fxp_session = NULL;
      return res;
    }

    if (have_cache) {
      fxp = fxp_packet_read(channel_id, NULL, NULL, &have_cache);
      continue;
    }

    fxp_session = NULL;
    return res;
  }

  fxp_session = NULL;
  return 0;
}

int sftp_fxp_set_displaylogin(const char *path) {
  pr_fh_t *fh;

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Support "DisplayLogin none", in case we need to disable support for
   * DisplayLogin files inherited from <Global> configurations.
   */
  if (strncasecmp(path, "none", 5) == 0) {
    return 0;
  }

  fh = pr_fsio_open(path, O_RDONLY);
  if (fh == NULL)
    return -1;

  fxp_displaylogin_fh = fh;
  return 0;
}

int sftp_fxp_set_extensions(unsigned long ext_flags) {
  fxp_ext_flags = ext_flags;
  return 0;
}

int sftp_fxp_set_protocol_version(unsigned int min_version,
    unsigned int max_version) {
  if ((min_version < 1 || min_version > 6) ||
      (max_version < 1 || max_version > 6)) {
    errno = EINVAL;
    return -1;
  }

  if (min_version > max_version) {
    errno = EINVAL;
    return -1;
  }

  fxp_min_client_version = min_version;
  fxp_max_client_version = max_version;
  return 0;
}

int sftp_fxp_set_utf8_protocol_version(unsigned int version) {
  if (version < 1 || version > 6) {
    errno = EINVAL;
    return -1;
  }

  fxp_utf8_protocol_version = version;
  return 0;
}

void sftp_fxp_use_gmt(int use_gmt) {
  fxp_use_gmt = use_gmt;
}

int sftp_fxp_open_session(uint32_t channel_id) {
  pool *sub_pool;
  struct fxp_session *sess, *last;

  /* Check to see if we already have an SFTP session opened for the given
   * channel ID.
   */
  sess = last = fxp_sessions;
  while (sess) {
    pr_signals_handle();

    if (sess->channel_id == channel_id) {
      errno = EEXIST;
      return -1;
    }

    if (sess->next == NULL) {
      /* This is the last item in the list. */
      last = sess;
    }

    sess = sess->next;
  }

  /* Looks like we get to allocate a new one. */
  sub_pool = make_sub_pool(fxp_pool);
  pr_pool_tag(sub_pool, "SFTP session pool");

  sess = pcalloc(sub_pool, sizeof(struct fxp_session));
  sess->pool = sub_pool;
  sess->channel_id = channel_id;

  if (last) {
    last->next = sess;
    sess->prev = last;

  } else {
    fxp_sessions = sess;
  }

  pr_event_generate("mod_sftp.sftp.session-opened", NULL);

  /* XXX Ignore any return value, for now. */
  (void) fxp_send_display_login_file(channel_id);

  pr_session_set_protocol("sftp");

  /* Clear any ASCII flags (set by default for FTP sessions. */
  session.sf_flags &= ~SF_ASCII;

  return 0;
}

int sftp_fxp_close_session(uint32_t channel_id) {
  struct fxp_session *sess;

  /* Check to see if we have an SFTP session opened for the given channel ID.
   */
  sess = fxp_sessions;
  while (sess) {
    pr_signals_handle();

    if (sess->channel_id == channel_id) {
      if (sess->next)
        sess->next->prev = sess->prev;

      if (sess->prev) {
        sess->prev->next = sess->next;

      } else {
        /* This is the start of the session list. */
        fxp_sessions = sess->next;
      }

      if (sess->handle_tab) {
        int count;

        count = pr_table_count(sess->handle_tab);
        if (count > 0) {
          int res;
          config_rec *c;
          void *callback_data = NULL;

          c = find_config(main_server->conf, CONF_PARAM, "DeleteAbortedStores",
            FALSE);
          if (c) {
            callback_data = c->argv[0];
          }

          (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
            "aborting %d unclosed file %s", count,
            count != 1 ? "handles" : "handle");

          /* Make sure that any abort processing has a valid response pool to
           * work with.
           */
          pr_response_set_pool(sess->pool);

          res = pr_table_do(sess->handle_tab, fxp_handle_abort, callback_data,
            PR_TABLE_DO_FL_ALL);
          if (res < 0) {
            (void) pr_log_writefile(sftp_logfd, MOD_SFTP_VERSION,
              "error doing session filehandle table: %s", strerror(errno));
          }
        }

        (void) pr_table_empty(sess->handle_tab);
        (void) pr_table_free(sess->handle_tab);
        sess->handle_tab = NULL;
      }

      destroy_pool(sess->pool);
      pr_session_set_protocol("ssh2");

      pr_event_generate("mod_sftp.sftp.session-closed", NULL);
      return 0;
    }

    sess = sess->next;
  }

  errno = ENOENT;
  return -1;
}
