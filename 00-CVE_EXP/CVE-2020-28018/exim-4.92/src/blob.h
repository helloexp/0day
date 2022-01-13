/*
 *  Blob - a general pointer/size item for a memory chunk
 *
 *  Copyright (C) 2016  Exim maintainers
 */

#ifndef BLOB_H	/* entire file */
#define BLOB_H

typedef struct {
  uschar * data;
  size_t   len;
} blob;

#endif
