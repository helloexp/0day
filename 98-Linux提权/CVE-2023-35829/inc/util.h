#ifndef _UTIL_H_
#define _UTIL_H_

#include <unistd.h>

#define FILENAME_MAX_LEN 0x80

void new_ns(void);
void set_cpu_affinity(int cpu_n, pid_t pid);
char *generate_tmp_filename(void);

#endif /* _UTIL_H_ */
