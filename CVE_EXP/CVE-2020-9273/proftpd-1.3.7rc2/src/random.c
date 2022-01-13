/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2017 The ProFTPD Project team
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

#include "conf.h"

int pr_random_init(void) {
#ifdef HAVE_RANDOM
  struct timeval tv;

  gettimeofday(&tv, NULL);
  srandom(getpid() ^ tv.tv_usec);
#else
  srand((unsigned int) (getpid() * time(NULL)));
#endif /* HAVE_RANDOM */

  return 0;
}

long pr_random_next(long min, long max) {
  long r, scaled;

#ifdef HAVE_RANDOM
  r = random();
#else
  r = (long) rand();
#endif /* HAVE_RANDOM */

  scaled = r % (max - min + 1) + min;
  return scaled;
}
