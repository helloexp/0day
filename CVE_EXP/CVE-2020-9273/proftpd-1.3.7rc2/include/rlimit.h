/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2013-2016 The ProFTPD Project team
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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Resource limits */

#ifndef PR_RLIMIT_H
#define PR_RLIMIT_H

/* Uses RLIMIT_CORE. */
int pr_rlimit_get_core(rlim_t *current, rlim_t *max);
int pr_rlimit_set_core(rlim_t current, rlim_t max);

/* Uses RLIMIT_CPU. */
int pr_rlimit_get_cpu(rlim_t *current, rlim_t *max);
int pr_rlimit_set_cpu(rlim_t current, rlim_t max);

/* Uses RLMIT_NOFILE or RLIMIT_OFILE. */
int pr_rlimit_get_files(rlim_t *current, rlim_t *max);
int pr_rlimit_set_files(rlim_t current, rlim_t max);

/* Uses RLIMIT_AS, RLIMIT_DATA, or RLIMIT_VMEM. */
int pr_rlimit_get_memory(rlim_t *current, rlim_t *max);
int pr_rlimit_set_memory(rlim_t current, rlim_t max);

/* Uses RLIMIT_NPROC. */
int pr_rlimit_get_nproc(rlim_t *current, rlim_t *max);
int pr_rlimit_set_nproc(rlim_t current, rlim_t max);

#endif /* PR_RLIMIT_H */
