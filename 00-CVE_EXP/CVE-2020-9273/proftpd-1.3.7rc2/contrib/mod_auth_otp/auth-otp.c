/*
 * auth-otp: HOTP/TOTP tool for ProFTPD mod_auth_otp module
 * Copyright 2016 The ProFTPD Project team
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

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#else
#  include "../lib/getopt.h"
#endif /* !HAVE_GETOPT_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "mod_auth_otp.h"
#include "pool.h"
#include "base32.h"
#include "crypto.h"
#include "otp.h"

static int quiet = FALSE, verbose = FALSE;

/* Necessary stubs. */

int auth_otp_logfd = -1;
pool *auth_otp_pool = NULL;

void pr_alarms_block(void) {
}

void pr_alarms_unblock(void) {
}

void pr_log_pri(int prio, const char *fmt, ...) {
  if (verbose) {
    va_list msg;

    fprintf(stderr, "PRI%d: ", prio);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

int pr_log_writefile(int fd, const char *prefix, const char *fmt, ...) {
  if (verbose) {
    va_list msg;

    fprintf(stderr, "%s: ", prefix);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }

  return 0;
}

void pr_memscrub(void *ptr, size_t ptrlen) {
  if (ptr == NULL ||
      ptrlen == 0) {
    return;
  }

  OPENSSL_cleanse(ptr, ptrlen);
}

module *pr_module_get(const char *name) {
  errno = ENOENT;
  return NULL;
}

void pr_signals_handle(void) {
}

int pr_snprintf(char *buf, size_t bufsz, const char *fmt, ...) {
  va_list msg;
  int res;

  va_start(msg, fmt);
  res = pr_vsnprintf(buf, bufsz, fmt, msg);
  va_end(msg);

  return res;
}

int pr_trace_msg(const char *name, int level, const char *fmt, ...) {
  if (verbose) {
    va_list msg;

    fprintf(stderr, "<%s:%d>: ", name, level);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }

  return 0;
}

int pr_vsnprintf(char *buf, size_t bufsz, const char *fmt, va_list msg) {
  return vsnprintf(buf, bufsz, fmt, msg);
}

static struct option_help {
  const char *long_opt, *short_opt, *desc;
} opts_help[] = {
  { "--help",	"-h",	NULL },
  { "--quiet",	"-q",	NULL },
  { "--verbose","-v",	NULL },
  { NULL }
};

#ifdef HAVE_GETOPT_LONG
static struct option opts[] = {
  { "help",    0, NULL, 'h' },
  { "quiet",   0, NULL, 'q' },
  { "verbose", 0, NULL, 'v' },
  { NULL,      0, NULL, 0   }
};
#endif /* HAVE_GETOPT_LONG */

static void show_usage(const char *progname, int exit_code) {
  struct option_help *h = NULL;

  printf("usage: %s [options]\n", progname);
  for (h = opts_help; h->long_opt; h++) {
#ifdef HAVE_GETOPT_LONG
    printf("  %s, %s\n", h->short_opt, h->long_opt);
#else /* HAVE_GETOPT_LONG */
    printf("  %s\n", h->short_opt);
#endif
    if (h->desc == NULL) {
      printf("    display %s usage\n", progname);

    } else {
      printf("    %s\n", h->desc);
    }
  }

  exit(exit_code);
}

static int generate_code(pool *p, const char *key, size_t key_len) {
  int res;
  unsigned int code;

  res = auth_otp_hotp(p, (const unsigned char *) key, key_len, 0, &code);
  if (res < 0) {
    return -1;
  }

  return (int) code;
}

static const char *generate_secret(pool *p) {
  int res;
  unsigned char encoded[18], rnd[32];
  size_t encoded_len;
  const char *secret;
  const unsigned char *ptr;

  if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
    fprintf(stderr, "Error obtaining %lu bytes of random data:\n",
      (unsigned long) sizeof(rnd));
    ERR_print_errors_fp(stderr);
    errno = EPERM;
    return NULL;
  }

  encoded_len = sizeof(encoded);
  ptr = encoded;
  res = auth_otp_base32_encode(p, rnd, sizeof(rnd), &ptr, &encoded_len);
  if (res < 0) {
    return NULL;
  }

  secret = pstrndup(p, (const char *) ptr, encoded_len);
  return secret;
}

int main(int argc, char **argv) {
  int c = 0;
  char *ptr, *progname = *argv;
  const char *cmdopts = "hqv", *secret = NULL;

  ptr = strrchr(progname, '/');
  if (ptr != NULL) {
    progname = ptr+1;
  }

  opterr = 0;
  while ((c =
#ifdef HAVE_GETOPT_LONG
	 getopt_long(argc, argv, cmdopts, opts, NULL)
#else /* HAVE_GETOPT_LONG */
	 getopt(argc, argv, cmdopts)
#endif /* HAVE_GETOPT_LONG */
	 ) != -1) {
    switch (c) {
      case 'h':
        show_usage(progname, 0);
        break;

      case 'q':
        verbose = FALSE;
        quiet = TRUE;
        break;

      case 'v':
        quiet = FALSE;
        verbose = TRUE;
        break;

      case '?':
        fprintf(stderr, "unknown option: %c\n", (char) optopt);
        show_usage(progname, 1);
        break;
    }
  }

  auth_otp_pool = make_sub_pool(NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  OPENSSL_config(NULL);
#endif /* prior to OpenSSL-1.1.x */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();

  secret = generate_secret(auth_otp_pool);  
  if (secret == NULL) {
    return 1;
  }

  if (quiet) {
    fprintf(stdout, "%s\n", secret);

  } else {
    int code;

    code = generate_code(auth_otp_pool, secret, strlen(secret));
    if (code < 0) {
      fprintf(stderr, "%s: error generating verification code: %s\n", progname,
        strerror(errno));
      destroy_pool(auth_otp_pool);
      return 1;
    }

    fprintf(stdout, "-------------------------------------------------\n");
    fprintf(stdout, "Your new secret key is: %s\n\n", secret);
    fprintf(stdout, "To add this key to your SQL table, you might use:\n\n");
    fprintf(stdout, "  INSERT INTO auth_otp (secret, counter) VALUES ('%s', 0);\n\n",
      secret);
    fprintf(stdout, "Your verification code is: %06d\n", code);
    fprintf(stdout, "-------------------------------------------------\n");
  }

  ERR_free_strings();
  EVP_cleanup();
  RAND_cleanup();

  destroy_pool(auth_otp_pool);
  return 0;
}
