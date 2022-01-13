/*
 * ProFTPD - mod_snmp uptime
 * Copyright (c) 2012-2016 TJ Saunders
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

#include "mod_snmp.h"
#include "uptime.h"

#ifdef HAVE_SYS_SYSCTL_H
# include <sys/sysctl.h>
#endif

#ifdef HAVE_SYS_SYSINFO_H
# include <sys/sysinfo.h>
#endif

#ifdef HAVE_SYSINFO
static int snmp_uptime_via_sysinfo(struct timeval *tv) {
  int res;
  struct sysinfo info;

  res = sysinfo(&info);
  if (res < 0) {
    return -1;
  }

  tv->tv_sec = info.uptime;
  tv->tv_usec = 0;

  return res;
}

#elif HAVE_SYSCTL
static int snmp_uptime_via_sysctl(struct timeval *tv) {
  int res;
  int mib[2];
  struct timeval boot_tv;
  size_t boot_tvlen;

  mib[0] = CTL_KERN;
  mib[1] = KERN_BOOTTIME;
  boot_tvlen = sizeof(boot_tv);

  res = sysctl(mib, 2, &boot_tv, &boot_tvlen, NULL, 0);
  if (res < 0) {
    return -1;
  }

  tv->tv_sec = boot_tv.tv_sec;
  tv->tv_usec = boot_tv.tv_usec;

  return res;
}
#endif /* No sysinfo(3), no sysctl(3) */

int snmp_uptime_get(pool *p, struct timeval *tv) {
  int res;

  if (p == NULL ||
      tv == NULL) {
    errno = EINVAL;
    return -1;
  }

#ifdef HAVE_SYSINFO
  res = snmp_uptime_via_sysinfo(tv);

#elif HAVE_SYSCTL
  res = snmp_uptime_via_sysctl(tv);

#else
  errno = ENOSYS;
  res = -1;
#endif

  return res;
}

