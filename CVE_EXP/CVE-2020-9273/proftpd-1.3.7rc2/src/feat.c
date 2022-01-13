/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2001-2016 The ProFTPD Project team
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

/* Feature management code */

#include "conf.h"

static pool *feat_pool = NULL;
static pr_table_t *feat_tab = NULL;

int pr_feat_add(const char *feat) {
  if (feat == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* If no feature-tracking list has been allocated, create one. */
  if (feat_pool == NULL) {
    feat_pool = make_sub_pool(permanent_pool);
    pr_pool_tag(feat_pool, "Feat API");
    feat_tab = pr_table_alloc(feat_pool, 0);
  }

  /* Make sure that the feature being added isn't already in the list. */
  if (pr_table_exists(feat_tab, feat) > 0) {
    errno = EEXIST;
    return -1;
  }

  return pr_table_add(feat_tab, pstrdup(feat_pool, feat), "", 0);
}

int pr_feat_remove(const char *feat) {
  const void *res;

  if (feat_tab == NULL) {
    errno = EPERM;
    return -1;
  }

  if (feat == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_table_remove(feat_tab, feat, NULL);
  if (res != NULL) {
    return 0;
  }

  errno = ENOENT;
  return -1;
}

const char *pr_feat_get(void) {
  if (feat_tab == NULL) {
    errno = EPERM;
    return NULL;
  }

  (void) pr_table_rewind(feat_tab);
  return pr_table_next(feat_tab);
}

const char *pr_feat_get_next(void) {
  if (feat_tab == NULL) {
    errno = EPERM;
    return NULL;
  }

  return pr_table_next(feat_tab);
}
