/*
 * SPDX-License-Identifier: ISC
 *
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_fatal.h"
#include "check.h"

__dso_public int main(int argc, char *argv[]);

#ifdef __linux__
static int
get_now(struct timespec *now)
{
    const char *errstr;
    char buf[1024];
    time_t seconds;
    int ret = -1;
    FILE *fp;

    /* Linux process start time is relative to boot time. */
    fp = fopen("/proc/stat", "r");
    if (fp != NULL) {
	while (fgets(buf, sizeof(buf), fp) != NULL) {
	    if (strncmp(buf, "btime ", 6) != 0)
		continue;
	    buf[strcspn(buf, "\n")] = '\0';

	    /* Boot time is in seconds since the epoch. */
	    seconds = sudo_strtonum(buf + 6, 0, TIME_T_MAX, &errstr);
	    if (errstr != NULL)
		return -1;

	    /* Instead of the real time, "now" is relative to boot time. */
	    if (sudo_gettime_real(now) == -1)
		return -1;
	    now->tv_sec -= seconds;
	    ret = 0;
	    break;
	}
	fclose(fp);
    }
    return ret;
}
#else
static int
get_now(struct timespec *now)
{
    /* Process start time is relative to wall clock time. */
    return sudo_gettime_real(now);
}
#endif

int
main(int argc, char *argv[])
{
    int ntests = 0, errors = 0;
    struct timespec now, then, delta;
    pid_t pids[2];
    int i;

    initprogname(argc > 0 ? argv[0] : "check_starttime");

    if (get_now(&now) == -1)
	sudo_fatal_nodebug("unable to get current time");

    pids[0] = getpid();
    pids[1] = getppid();

    for (i = 0; i < 2; i++) {
	ntests++;
	if (get_starttime(pids[i], &then)  == -1) {
	    printf("%s: test %d: unable to get start time for pid %d\n",
		getprogname(), ntests, (int)pids[i]);
	    errors++;
	}
	if (i != 0)
	    continue;

	/* Verify our own process start time, allowing for some drift. */
	ntests++;
	sudo_timespecsub(&then, &now, &delta);
	if (delta.tv_sec > 30 || delta.tv_sec < -30) {
	    printf("%s: test %d: unexpected start time for pid %d: %s",
		getprogname(), ntests, (int)pids[i], ctime(&then.tv_sec));
	    errors++;
	}
    }

    printf("%s: %d tests run, %d errors, %d%% success rate\n", getprogname(),
	ntests, errors, (ntests - errors) * 100 / ntests);

    exit(errors);
}
