/*
 * Copyright (c) 2017 Todd C. Miller <Todd.Miller@sudo.ws>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif
#include <errno.h>

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_util.h"

__dso_public int main(int argc, char *argv[]);

/*
 * Test that sudo_vsyslog() works as expected.
 */
static char *expected_result;
static int errors;
static int ntests;

/*
 * Dummy version of syslog to verify the message
 */
void
syslog(int priority, const char *fmt, ...)
{
    va_list ap;
    const char *msg;

    if (strcmp(fmt, "%s") != 0)
	sudo_fatalx_nodebug("Expected syslog format \"%%s\", got \"%s\"", fmt);

    va_start(ap, fmt);
    msg = va_arg(ap, char *);
    if (strcmp(msg, expected_result) != 0) {
	sudo_warnx_nodebug("Expected \"%s\", got \"%s\"", expected_result, msg);
	errors++;
    } else {
	ntests++;
    }
    va_end(ap);
}

static void
test_vsyslog(int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    sudo_vsyslog(priority, fmt, ap);
    va_end(ap);
}

int
main(int argc, char *argv[])
{
    char buf1[1024 * 16], buf2[1024 * 16];
    initprogname(argc > 0 ? argv[0] : "vsyslog_test");

    /* Test small buffer. */
    expected_result = "sudo:  millert : TTY=ttypa ; PWD=/etc/mail ; USER=root ; TSID=000AB0 ; COMMAND=/usr/sbin/newaliases";
    test_vsyslog(0,
	"%s:  %s : TTY=%s ; PWD=%s ; USER=%s ; TSID=%s ; COMMAND=%s",
	"sudo", "millert", "ttypa", "/etc/mail", "root", "000AB0",
	"/usr/sbin/newaliases");

    /* Test small buffer w/ errno. */
    snprintf(buf1, sizeof(buf1),
	 "unable to open %s: %s", "/var/log/sudo-io/seq", strerror(ENOENT));
    expected_result = buf1;
    errno = ENOENT;
    test_vsyslog(0, "unable to open %s: %m", "/var/log/sudo-io/seq");

    /* Test large buffer > 8192 bytes. */
    memset(buf1, 'a', 8192);
    buf1[8192] = '\0';
    expected_result = buf1;
    test_vsyslog(0, "%s", buf1);

    /* Test large buffer w/ errno > 8192 bytes. */
    memset(buf1, 'b', 8184);
    buf1[8184] = '\0';
    snprintf(buf2, sizeof(buf2), "%s: %s", buf1, strerror(EINVAL));
    expected_result = buf2;
    errno = EINVAL;
    test_vsyslog(0, "%s: %m", buf1);

    /* Test large format string > 8192 bytes, expect truncation to 2048. */
    memset(buf1, 'b', 8184);
    buf1[8184] = '\0';
    snprintf(buf2, sizeof(buf2), "%.*s", 2047, buf1);
    expected_result = buf2;
    test_vsyslog(0, buf1);

    if (ntests != 0) {
	printf("%s: %d tests run, %d errors, %d%% success rate\n",
	    getprogname(), ntests, errors, (ntests - errors) * 100 / ntests);
    } else {
	printf("%s: error, no tests run!\n", getprogname());
	errors = 1;
    }
    exit(errors);
}
