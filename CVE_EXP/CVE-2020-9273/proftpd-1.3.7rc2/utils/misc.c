/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
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
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

/* Utility module linked to utilities to provide functions normally
 * present in full src tree.
 */

#include "utils.h"

/* "safe" strncpy, saves room for \0 at end of dest, and refuses to copy
 * more than "n" bytes.
 */
char *util_sstrncpy(char *dest, const char *src, size_t n) {
  register char *d = dest;

  if (!dest)
    return NULL;

  if (n == 0)
    return NULL;

  if (src && *src) {
    for (; *src && n > 1; n--)
      *d++ = *src++;
  }

  *d = '\0';

  return dest;
}

char *util_scan_config(const char *config_path, const char *directive) {
  FILE *fp = NULL;
  char buf[PR_TUNABLE_BUFFER_SIZE] = {'\0'};
  char *cp, *value = NULL;

  if (!config_path || !directive) {
    errno = EINVAL;
    return NULL;
  }

  fp = fopen(config_path, "r");
  if (fp == NULL)
    return NULL;
  
  while (!value && fgets(buf, sizeof(buf) - 1, fp)) {
    size_t len = strlen(buf);

    if (len &&
        buf[len-1] == '\n')
      buf[len-1] = '\0';

    for (cp = buf; *cp && PR_ISSPACE(*cp); cp++);

    if (*cp == '#' ||
        !*cp)
      continue;

    len = strlen(directive);

    if (strncasecmp(cp, directive, len) != 0)
      continue;

    /* Found it! */
    cp += len;

    /* strip whitespace */
    while (*cp && PR_ISSPACE(*cp)) {
      cp++;
    }

    value = cp;

    /* If the value is quoted, dequote. */
    if (*cp == '"') {
      char *src = cp;

      cp++;
      value++;

      while (*++src) {
        switch (*src) {
          case '\\':
            if (*++src)
              *cp++ = *src;
            break;

          case '"':
            src++;
            break;

          default:
            *cp++ = *src;
        }
      }

      *cp = '\0';
    }
  }

  fclose(fp);

  return value ? strdup(value) : NULL;
}
