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
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* JSON API */

#ifndef PR_JSON_H
#define PR_JSON_H

#include "conf.h"

typedef struct json_list_st pr_json_array_t;
typedef struct json_obj_st pr_json_object_t;

/* JSON Types */

#define PR_JSON_TYPE_BOOL		1
#define PR_JSON_TYPE_NUMBER		2
#define PR_JSON_TYPE_NULL		3
#define PR_JSON_TYPE_STRING		4
#define PR_JSON_TYPE_ARRAY		5
#define PR_JSON_TYPE_OBJECT		6

/* JSON Objects */

pr_json_object_t *pr_json_object_alloc(pool *p);

int pr_json_object_free(pr_json_object_t *json);

pr_json_object_t *pr_json_object_from_text(pool *p, const char *text);

char *pr_json_object_to_text(pool *p, const pr_json_object_t *json,
  const char *indent);

/* Returns the number of members (keys) in the given object. */
int pr_json_object_count(const pr_json_object_t *json);

/* Removes the object member under this key. */
int pr_json_object_remove(pr_json_object_t *json, const char *key);

/* Checks where a member under the given key exists.  Returns TRUE, FALSE,
 * or -1 is there was some other error.
 */
int pr_json_object_exists(const pr_json_object_t *json, const char *key);

int pr_json_object_get_bool(pool *p, const pr_json_object_t *json,
  const char *key, int *val);
int pr_json_object_set_bool(pool *p, pr_json_object_t *json, const char *key,
  int val);

int pr_json_object_get_null(pool *p, const pr_json_object_t *json,
  const char *key);
int pr_json_object_set_null(pool *p, pr_json_object_t *json, const char *key);

int pr_json_object_get_number(pool *p, const pr_json_object_t *json,
  const char *key, double *val);
int pr_json_object_set_number(pool *p, pr_json_object_t *json, const char *key,
  double val);

int pr_json_object_get_string(pool *p, const pr_json_object_t *json,
  const char *key, char **val);
int pr_json_object_set_string(pool *p, pr_json_object_t *json, const char *key,
  const char *val);

int pr_json_object_get_array(pool *p, const pr_json_object_t *json,
  const char *key, pr_json_array_t **val);
int pr_json_object_set_array(pool *p, pr_json_object_t *json, const char *key,
  const pr_json_array_t *val);

int pr_json_object_get_object(pool *p, const pr_json_object_t *json,
  const char *key, pr_json_object_t **val);
int pr_json_object_set_object(pool *p, pr_json_object_t *json, const char *key,
  const pr_json_object_t *val);

/* JSON Arrays */

pr_json_array_t *pr_json_array_alloc(pool *p);

int pr_json_array_free(pr_json_array_t *json);

pr_json_array_t *pr_json_array_from_text(pool *p, const char *text);

char *pr_json_array_to_text(pool *p, const pr_json_array_t *json,
  const char *indent);

/* Returns the number of items in the given array. */
int pr_json_array_count(const pr_json_array_t *json);

/* Removes the array item under this key. */
int pr_json_array_remove(pr_json_array_t *json, unsigned int idx);

/* Checks where an item at the given index exists.  Returns TRUE, FALSE,
 * or -1 is there was some other error.
 */
int pr_json_array_exists(const pr_json_array_t *json, unsigned int idx);

int pr_json_array_append_bool(pool *p, pr_json_array_t *json, int val);
int pr_json_array_get_bool(pool *p, const pr_json_array_t *json,
  unsigned int idx, int *val);

int pr_json_array_append_null(pool *p, pr_json_array_t *json);
int pr_json_array_get_null(pool *p, const pr_json_array_t *json,
  unsigned int idx);

int pr_json_array_append_number(pool *p, pr_json_array_t *json, double val);
int pr_json_array_get_number(pool *p, const pr_json_array_t *json,
  unsigned int idx, double *val);

int pr_json_array_append_string(pool *p, pr_json_array_t *json,
  const char *val);
int pr_json_array_get_string(pool *p, const pr_json_array_t *json,
  unsigned int idx, char **val);

int pr_json_array_append_array(pool *p, pr_json_array_t *json,
  const pr_json_array_t *val);
int pr_json_array_get_array(pool *p, const pr_json_array_t *json,
  unsigned int idx, pr_json_array_t **val);

int pr_json_array_append_object(pool *p, pr_json_array_t *json,
  const pr_json_object_t *val);
int pr_json_array_get_object(pool *p, const pr_json_array_t *json,
  unsigned int idx, pr_json_object_t **val);

/* Miscellaneous */

/* Validates that the given text is a valid JSON string. */
int pr_json_text_validate(pool *p, const char *text);

/* Provides textual label of the JSON type. */
const char *pr_json_type_name(unsigned int json_type);

/* Internal use only. */
int init_json(void);
int finish_json(void);

#endif /* PR_JSON_H */
