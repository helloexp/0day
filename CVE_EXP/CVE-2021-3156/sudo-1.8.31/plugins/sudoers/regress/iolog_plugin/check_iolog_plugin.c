/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <errno.h>
#include <pwd.h>
#include <time.h>
#include <unistd.h>

#define SUDO_ERROR_WRAP 0

#include "sudoers.h"
#include "def_data.c"		/* for iolog_path.c */
#include "sudo_plugin.h"
#include "iolog.h"

extern struct io_plugin sudoers_io;

struct sudo_user sudo_user;
struct passwd *list_pw;
sudo_printf_t sudo_printf;
sudo_conv_t sudo_conv;

__dso_public int main(int argc, char *argv[], char *envp[]);

static void
usage(void)
{
    fprintf(stderr, "usage: %s pathname\n", getprogname());
    exit(1);
}

static int
sudo_printf_int(int msg_type, const char *fmt, ...)
{
    va_list ap;
    int len;

    switch (msg_type) {
    case SUDO_CONV_INFO_MSG:
	va_start(ap, fmt);
	len = vfprintf(stdout, fmt, ap);
	va_end(ap);
	break;
    case SUDO_CONV_ERROR_MSG:
	va_start(ap, fmt);
	len = vfprintf(stderr, fmt, ap);
	va_end(ap);
	break;
    default:
	len = -1;
	errno = EINVAL;
	break;
    }

    return len;
}

bool
validate_iolog_info(const char *logfile)
{
    time_t now;
    struct log_info *info;

    time(&now);

    /* Parse log file. */
    if ((info = parse_logfile(logfile)) == NULL)
	return false;

    if (strcmp(info->cwd, "/") != 0) {
	sudo_warnx("bad cwd: want \"/\", got \"%s\"", info->cwd);
	return false;
    }

    if (strcmp(info->user, "nobody") != 0) {
	sudo_warnx("bad user: want \"nobody\" got \"%s\"", info->user);
	return false;
    }

    if (strcmp(info->runas_user, "root") != 0) {
	sudo_warnx("bad runas_user: want \"root\" got \"%s\"", info->runas_user);
	return false;
    }

    if (info->runas_group != NULL) {
	sudo_warnx("bad runas_group: want \"\" got \"%s\"", info->runas_user);
	return false;
    }

    if (strcmp(info->tty, "/dev/console") != 0) {
	sudo_warnx("bad tty: want \"/dev/console\" got \"%s\"", info->tty);
	return false;
    }

    if (strcmp(info->cmd, "/usr/bin/id") != 0) {
	sudo_warnx("bad command: want \"/usr/bin/id\" got \"%s\"", info->cmd);
	return false;
    }

    if (info->rows != 24) {
	sudo_warnx("bad rows: want 24 got %d", info->rows);
	return false;
    }

    if (info->cols != 80) {
	sudo_warnx("bad cols: want 80 got %d", info->cols);
	return false;
    }

    if (info->tstamp < now - 10 || info->tstamp > now + 10) {
	sudo_warnx("bad tstamp: want %lld got %lld", (long long)now,
	    (long long)info->tstamp);
	return false;
    }

    free_log_info(info);

    return true;
}

bool
validate_timing(FILE *fp, int recno, int type, unsigned int p1, unsigned int p2)
{
    struct timing_closure timing;
    char buf[LINE_MAX];
    struct timespec delay;

    if (!fgets(buf, sizeof(buf), fp)) {
	sudo_warn("unable to read timing file");
	return false;
    }
    buf[strcspn(buf, "\n")] = '\0';
    if (!parse_timing(buf, &delay, &timing)) {
	sudo_warnx("invalid timing file line: %s", buf);
	return false;
    }
    if (timing.event != type) {
	sudo_warnx("record %d: want type %d, got type %d", recno, type,
	    timing.event);
	return false;
    }
    if (type == IO_EVENT_WINSIZE) {
	if (timing.u.winsize.rows != (int)p1) {
	    sudo_warnx("record %d: want %u rows, got %u", recno, p1,
		timing.u.winsize.rows);
	    return false;
	}
	if (timing.u.winsize.cols != (int)p2) {
	    sudo_warnx("record %d: want %u cols, got %u", recno, p2,
		timing.u.winsize.cols);
	    return false;
	}
    } else {
	if (timing.u.nbytes != p1) {
	    sudo_warnx("record %d: want len %u, got type %zu", recno, p1,
		timing.u.nbytes);
	    return false;
	}
    }
    if (delay.tv_sec != 0 || delay.tv_nsec > 10000000) {
	sudo_warnx("record %d: got excessive delay %lld.%09ld", recno,
	    (long long)delay.tv_sec, delay.tv_nsec);
	return false;
    }

    return true;
}


/*
 * Test sudoers I/O log plugin endpoints.
 */
void
test_endpoints(int *ntests, int *nerrors, const char *iolog_dir, char *envp[])
{
    int rc, cmnd_argc = 1;
    char buf[1024], iolog_path[PATH_MAX];
    char runas_gid[64], runas_uid[64];
    FILE *fp;
    char *cmnd_argv[] = {
	"/usr/bin/id",
	NULL
    };
    char *user_info[] = {
	"cols=80",
	"lines=24",
	"cwd=/",
	"tty=/dev/console",
	"user=nobody",
	NULL
    };
    char *command_info[] = {
	"command=/usr/bin/id",
	iolog_path,
	"iolog_stdin=true",
	"iolog_stdout=true",
	"iolog_stderr=true",
	"iolog_ttyin=true",
	"iolog_ttyout=true",
	"iolog_compress=false",
	"iolog_mode=0644",
	runas_gid,
	runas_uid,
	NULL
    };
    char *settings[] = {
	NULL
    };
    const char output[] = "uid=0(root) gid=0(wheel)\r\n";

    /* Set runas uid/gid to root. */
    snprintf(runas_uid, sizeof(runas_uid), "runas_uid=%u",
	(unsigned int)runas_pw->pw_uid);
    snprintf(runas_gid, sizeof(runas_gid), "runas_gid=%u",
	(unsigned int)runas_pw->pw_gid);

    /* Set path to the iolog directory the user passed in. */
    snprintf(iolog_path, sizeof(iolog_path), "iolog_path=%s", iolog_dir);

    /* Test open endpoint. */
    rc = sudoers_io.open(SUDO_API_VERSION, NULL, sudo_printf_int, settings,
	user_info, command_info, cmnd_argc, cmnd_argv, envp, NULL);
    (*ntests)++;
    if (rc != 1) {
	sudo_warnx("I/O log open endpoint failed");
	(*nerrors)++;
	return;
    }

    /* Validate I/O log info file. */
    (*ntests)++;
    snprintf(iolog_path, sizeof(iolog_path), "%s/log", iolog_dir);
    if (!validate_iolog_info(iolog_path))
	(*nerrors)++;

    /* Test log_ttyout endpoint. */
    rc = sudoers_io.log_ttyout(output, strlen(output));
    (*ntests)++;
    if (rc != 1) {
	sudo_warnx("I/O log_ttyout endpoint failed");
	(*nerrors)++;
	return;
    }

    /* Test change_winsize endpoint (twice). */
    rc = sudoers_io.change_winsize(32, 128);
    (*ntests)++;
    if (rc != 1) {
	sudo_warnx("I/O change_winsize endpoint failed");
	(*nerrors)++;
	return;
    }
    rc = sudoers_io.change_winsize(24, 80);
    (*ntests)++;
    if (rc != 1) {
	sudo_warnx("I/O change_winsize endpoint failed");
	(*nerrors)++;
	return;
    }

    /* Close the plugin. */
    sudoers_io.close(0, 0);

    /* Validate the timing file. */
    snprintf(iolog_path, sizeof(iolog_path), "%s/timing", iolog_dir);
    (*ntests)++;
    if ((fp = fopen(iolog_path, "r")) == NULL) {
	sudo_warn("unable to open %s", iolog_path);
	(*nerrors)++;
	return;
    }

    /* Line 1: output of id command. */
    if (!validate_timing(fp, 1, IO_EVENT_TTYOUT, strlen(output), 0)) {
	(*nerrors)++;
	return;
    }

    /* Line 2: window size change. */
    if (!validate_timing(fp, 2, IO_EVENT_WINSIZE, 32, 128)) {
	(*nerrors)++;
	return;
    }

    /* Line 3: window size change. */
    if (!validate_timing(fp, 3, IO_EVENT_WINSIZE, 24, 80)) {
	(*nerrors)++;
	return;
    }

    /* Validate ttyout log file. */
    snprintf(iolog_path, sizeof(iolog_path), "%s/ttyout", iolog_dir);
    (*ntests)++;
    fclose(fp);
    if ((fp = fopen(iolog_path, "r")) == NULL) {
	sudo_warn("unable to open %s", iolog_path);
	(*nerrors)++;
	return;
    }
    if (!fgets(buf, sizeof(buf), fp)) {
	sudo_warn("unable to read %s", iolog_path);
	(*nerrors)++;
	return;
    }
    if (strcmp(buf, output) != 0) {
	sudo_warnx("ttylog mismatch: want \"%s\", got \"%s\"", output, buf);
	(*nerrors)++;
	return;
    }
}

int
main(int argc, char *argv[], char *envp[])
{
    struct passwd pw, rpw, *tpw;
    int tests = 0, errors = 0;
    const char *iolog_dir;

    initprogname(argc > 0 ? argv[0] : "check_iolog_plugin");

    if (argc != 2)
	usage();
    iolog_dir = argv[1];

    /* Bare minimum to link. */
    memset(&pw, 0, sizeof(pw));
    memset(&rpw, 0, sizeof(rpw));
    if ((tpw = getpwuid(0)) == NULL) {
	if ((tpw = getpwnam("root")) == NULL)
	    sudo_fatalx("unable to look up uid 0 or root");
    }
    rpw.pw_uid = tpw->pw_uid;
    rpw.pw_gid = tpw->pw_gid;
    sudo_user.pw = &pw;
    sudo_user._runas_pw = &rpw;

    /* Set iolog uid/gid to invoking user. */
    iolog_uid = geteuid();
    iolog_gid = getegid();

    test_endpoints(&tests, &errors, iolog_dir, envp);

    if (tests != 0) {
	printf("check_iolog_plugin: %d test%s run, %d errors, %d%% success rate\n",
	    tests, tests == 1 ? "" : "s", errors,
	    (tests - errors) * 100 / tests);
    }

    exit(errors);
}

/* Stub functions */

bool
set_perms(int perm)
{
    return true;
}

bool
restore_perms(void)
{
    return true;
}

bool
log_warning(int flags, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    sudo_vwarn_nodebug(fmt, ap);
    va_end(ap);

    return true;
}

bool
log_warningx(int flags, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    sudo_vwarnx_nodebug(fmt, ap);
    va_end(ap);

    return true;
}
