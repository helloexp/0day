/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2008-2016 The ProFTPD Project team
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

/* Expression API definition */

#ifndef PR_EXPR_H
#define PR_EXPR_H

#include "pool.h"

/* For the different types of expressions: AND, OR, and REGEX. */
#define PR_EXPR_EVAL_AND	0
#define PR_EXPR_EVAL_OR		1
#define PR_EXPR_EVAL_REGEX	2

/* Parses the strings in argv, a NULL-terminated list of count argc,
 * into an array header.  If a given string is comma-delimited, then it
 * it is tokenized into the individual elements in the returned array.
 * Note that NULL is returned if there is an error (with errno set
 * appropriately), or if argc is less than or equal to zero.
 *
 * IMPORTANT: The first string in argv is automatically skipped, on the
 * assumption that it is a configuration directive.  This is NOT what
 * would expect from the API.  Callers of this function MUST take this
 * into account.
 */
array_header *pr_expr_create(pool *p, unsigned int *argc, char **argv);

int pr_expr_eval_class_and(char **);
int pr_expr_eval_class_or(char **);
int pr_expr_eval_group_and(char **);
int pr_expr_eval_group_or(char **);
int pr_expr_eval_user_and(char **);
int pr_expr_eval_user_or(char **);

#endif /* PR_EXPR_H */
