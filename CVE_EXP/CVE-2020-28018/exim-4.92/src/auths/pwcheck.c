/* SASL server API implementation
 * Rob Siemborski
 * Tim Martin
 * $Id: checkpw.c,v 1.49 2002/03/07 19:14:04 ken3 Exp $
 */
/*
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Taken from Cyrus-SASL library and adapted by Alexander S. Sabourenkov
 * Oct 2001 - Apr 2002: Slightly modified by Philip Hazel.
 * Aug 2003: new code for saslauthd from Alexander S. Sabourenkov incorporated
 *           by Philip Hazel (minor mods to avoid compiler warnings)
 * Oct 2006: (PH) removed redundant tests on "reply" being NULL - some were
 *           missing, and confused someone who was using this code for some
 *           other purpose. Here in Exim, "reply" is never NULL.
 *
 * screwdriver@lxnt.info
 *
 */

/* Originally this module supported only the pwcheck daemon, which is where its
name comes from. Nowadays it supports saslauthd as well; pwcheck is in fact
deprecated. The definitions of CYRUS_PWCHECK_SOCKET and CYRUS_SASLAUTHD_SOCKET
determine whether the facilities are actually supported or not. */


#include "../exim.h"
#include "pwcheck.h"


#if defined(CYRUS_PWCHECK_SOCKET) || defined(CYRUS_SASLAUTHD_SOCKET)

#include <sys/uio.h>

static int retry_read(int, void *, unsigned );
static int retry_writev(int, struct iovec *, int );
static int read_string(int, uschar **);
static int write_string(int, const uschar *, int);

#endif


/* A dummy function that always fails if pwcheck support is not
wanted. */

#ifndef CYRUS_PWCHECK_SOCKET
int pwcheck_verify_password(const char *userid,
                            const char *passwd,
                            const char **reply)
{
userid = userid;  /* Keep picky compilers happy */
passwd = passwd;
*reply = "pwcheck support is not included in this Exim binary";
return PWCHECK_FAIL;
}


/* This is the real function */

#else

 /* taken from cyrus-sasl file checkpw.c */
 /* pwcheck daemon-authenticated login */
 int pwcheck_verify_password(const char *userid,
                                  const char *passwd,
                                  const char **reply)
 {
     int s, start, r, n;
     struct sockaddr_un srvaddr;
     struct iovec iov[2];
     static char response[1024];

     *reply = NULL;

     s = socket(AF_UNIX, SOCK_STREAM, 0);
     if (s == -1) { return PWCHECK_FAIL; }

     memset(CS &srvaddr, 0, sizeof(srvaddr));
     srvaddr.sun_family = AF_UNIX;
     strncpy(srvaddr.sun_path, CYRUS_PWCHECK_SOCKET, sizeof(srvaddr.sun_path));
     r = connect(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
     if (r == -1) {
        DEBUG(D_auth)
            debug_printf("Cannot connect to pwcheck daemon (at '%s')\n",CYRUS_PWCHECK_SOCKET);
       *reply = "cannot connect to pwcheck daemon";
       return PWCHECK_FAIL;
     }

     iov[0].iov_base = CS userid;
     iov[0].iov_len = strlen(userid)+1;
     iov[1].iov_base = CS passwd;
     iov[1].iov_len = strlen(passwd)+1;

     retry_writev(s, iov, 2);

     start = 0;
     while (start < sizeof(response) - 1) {
       n = read(s, response+start, sizeof(response) - 1 - start);
       if (n < 1) break;
       start += n;
     }

     (void)close(s);

     if (start > 1 && !strncmp(response, "OK", 2)) {
       return PWCHECK_OK;
     }

     response[start] = '\0';
     *reply = response;
     return PWCHECK_NO;
 }

#endif



 /* A dummy function that always fails if saslauthd support is not
wanted. */

#ifndef CYRUS_SASLAUTHD_SOCKET
int saslauthd_verify_password(const uschar *userid,
                const uschar *passwd,
                const uschar *service,
                const uschar *realm,
                const uschar **reply)
{
userid = userid;  /* Keep picky compilers happy */
passwd = passwd;
service = service;
realm = realm;
*reply = US"saslauthd support is not included in this Exim binary";
return PWCHECK_FAIL;
}


/* This is the real function */

#else
 /* written from scratch  */
 /* saslauthd daemon-authenticated login */

int saslauthd_verify_password(const uschar *userid,
                const uschar *password,
                const uschar *service,
                const uschar *realm,
                const uschar **reply)
{
    uschar *daemon_reply = NULL;
    int s, r;
    struct sockaddr_un srvaddr;

    DEBUG(D_auth)
       debug_printf("saslauthd userid='%s' servicename='%s'"
                    " realm='%s'\n", userid, service, realm );

    *reply = NULL;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
       *reply = CUstrerror(errno);
       return PWCHECK_FAIL;
    }

    memset(CS &srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strncpy(srvaddr.sun_path, CYRUS_SASLAUTHD_SOCKET,
            sizeof(srvaddr.sun_path));
    r = connect(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    if (r == -1) {
       DEBUG(D_auth)
            debug_printf("Cannot connect to saslauthd daemon (at '%s'): %s\n",
                         CYRUS_SASLAUTHD_SOCKET, strerror(errno));
       *reply = string_sprintf("cannot connect to saslauthd daemon at "
                               "%s: %s", CYRUS_SASLAUTHD_SOCKET,
                               strerror(errno));
       return PWCHECK_FAIL;
    }

    if ( write_string(s, userid, Ustrlen(userid)) < 0) {
        DEBUG(D_auth)
            debug_printf("Failed to send userid to saslauthd daemon \n");
        (void)close(s);
        return PWCHECK_FAIL;
    }

    if ( write_string(s, password, Ustrlen(password)) < 0) {
        DEBUG(D_auth)
            debug_printf("Failed to send password to saslauthd daemon \n");
        (void)close(s);
        return PWCHECK_FAIL;
    }

    memset((void *)password, 0, Ustrlen(password));

    if ( write_string(s, service, Ustrlen(service)) < 0) {
        DEBUG(D_auth)
            debug_printf("Failed to send service name to saslauthd daemon \n");
        (void)close(s);
        return PWCHECK_FAIL;
    }

    if ( write_string(s, realm, Ustrlen(realm)) < 0) {
        DEBUG(D_auth)
            debug_printf("Failed to send realm to saslauthd daemon \n");
        (void)close(s);
        return PWCHECK_FAIL;
    }

    if ( read_string(s, &daemon_reply ) < 2) {
        DEBUG(D_auth)
            debug_printf("Corrupted answer '%s' received. \n", daemon_reply);
        (void)close(s);
        return PWCHECK_FAIL;
    }

    (void)close(s);

    DEBUG(D_auth)
        debug_printf("Answer '%s' received. \n", daemon_reply);

    *reply = daemon_reply;

    if ( (daemon_reply[0] == 'O') && (daemon_reply[1] == 'K') )
        return PWCHECK_OK;

    if ( (daemon_reply[0] == 'N') && (daemon_reply[1] == 'O') )
        return PWCHECK_NO;

    return PWCHECK_FAIL;
}

#endif


/* helper functions */
#if defined(CYRUS_PWCHECK_SOCKET) || defined(CYRUS_SASLAUTHD_SOCKET)

#define MAX_REQ_LEN 1024

/* written from scratch */

/* FUNCTION: read_string */

/* SYNOPSIS
 * read a sasld-style counted string into
 * store-allocated buffer, set pointer to the buffer,
 * return number of bytes read or -1 on failure.
 * END SYNOPSIS */

static int read_string(int fd, uschar **retval) {
    unsigned short count;
    int rc;

    rc = (retry_read(fd, &count, sizeof(count)) < (int) sizeof(count));
    if (!rc) {
        count = ntohs(count);
        if (count > MAX_REQ_LEN) {
            return -1;
        } else {
            *retval = store_get(count + 1);
            rc = (retry_read(fd, *retval, count) < (int) count);
            (*retval)[count] = '\0';
            return count;
        }
    }
    return -1;
}


/* FUNCTION: write_string */

/* SYNOPSIS
 * write a sasld-style counted string into given fd
 * written bytes on success, -1 on failure.
 * END SYNOPSIS */

static int write_string(int fd, const uschar *string, int len) {
    unsigned short count;
    int rc;
    struct iovec iov[2];

    count = htons(len);

    iov[0].iov_base = (void *) &count;
    iov[0].iov_len = sizeof(count);
    iov[1].iov_base = (void *) string;
    iov[1].iov_len = len;

    rc = retry_writev(fd, iov, 2);

    return rc;
}


/* taken from cyrus-sasl file saslauthd/saslauthd-unix.c  */

/* FUNCTION: retry_read */

/* SYNOPSIS
 * Keep calling the read() system call with 'fd', 'buf', and 'nbyte'
 * until all the data is read in or an error occurs.
 * END SYNOPSIS */
static int retry_read(int fd, void *inbuf, unsigned nbyte)
{
    int n;
    int nread = 0;
    char *buf = CS inbuf;

    if (nbyte == 0) return 0;

    for (;;) {
       n = read(fd, buf, nbyte);
       if (n == 0) {
           /* end of file */
           return -1;
       }
       if (n == -1) {
           if (errno == EINTR) continue;
           return -1;
       }

       nread += n;

       if (n >= (int) nbyte) return nread;

       buf += n;
       nbyte -= n;
    }
}

/* END FUNCTION: retry_read */

/* FUNCTION: retry_writev */

/* SYNOPSIS
 * Keep calling the writev() system call with 'fd', 'iov', and 'iovcnt'
 * until all the data is written out or an error occurs.
 * END SYNOPSIS */

static int     /* R: bytes written, or -1 on error */
retry_writev (
  /* PARAMETERS */
  int fd,                              /* I: fd to write on */
  struct iovec *iov,                   /* U: iovec array base
                                        *    modified as data written */
  int iovcnt                           /* I: number of iovec entries */
  /* END PARAMETERS */
  )
{
    /* VARIABLES */
    int n;                             /* return value from writev() */
    int i;                             /* loop counter */
    int written;                       /* bytes written so far */
    static int iov_max;                        /* max number of iovec entries */
    /* END VARIABLES */

    /* initialization */
#ifdef MAXIOV
    iov_max = MAXIOV;
#else /* ! MAXIOV */
# ifdef IOV_MAX
    iov_max = IOV_MAX;
# else /* ! IOV_MAX */
    iov_max = 8192;
# endif /* ! IOV_MAX */
#endif /* ! MAXIOV */
    written = 0;

    for (;;) {

       while (iovcnt && iov[0].iov_len == 0) {
           iov++;
           iovcnt--;
       }

       if (!iovcnt) {
           return written;
       }

       n = writev(fd, iov, iovcnt > iov_max ? iov_max : iovcnt);
       if (n == -1) {
           if (errno == EINVAL && iov_max > 10) {
               iov_max /= 2;
               continue;
           }
           if (errno == EINTR) {
               continue;
           }
           return -1;
       } else {
           written += n;
       }

       for (i = 0; i < iovcnt; i++) {
           if (iov[i].iov_len > (unsigned) n) {
               iov[i].iov_base = CS iov[i].iov_base + n;
               iov[i].iov_len -= n;
               break;
           }
           n -= iov[i].iov_len;
           iov[i].iov_len = 0;
       }

       if (i == iovcnt) {
           return written;
       }
    }
    /* NOTREACHED */
}

/* END FUNCTION: retry_writev */
#endif

/* End of auths/pwcheck.c */
