/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
 * Exim - CDB database lookup module
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Copyright (c) 1998 Nigel Metheringham, Planet Online Ltd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * --------------------------------------------------------------
 * Modified by PH for Exim 4:
 *   Changed over to using unsigned chars
 *   Makes use of lf_check_file() for file checking
 * --------------------------------------------------------------
 * Modified by The Exim Maintainers 2015:
 *   const propagation
 * --------------------------------------------------------------
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 *
 * This code implements Dan Bernstein's Constant DataBase (cdb) spec.
 * Information, the spec and sample code for cdb can be obtained from
 *      http://www.pobox.com/~djb/cdb.html
 *
 * This implementation borrows some code from Dan Bernstein's
 * implementation (which has no license restrictions applied to it).
 * This (read-only) implementation is completely contained within
 * cdb.[ch] it does *not* link against an external cdb library.
 *
 *
 * There are 2 variants included within this code.  One uses MMAP and
 * should give better performance especially for multiple lookups on a
 * modern machine.  The other is the default implementation which is
 * used in the case where the MMAP fails or if MMAP was not compiled
 * in.  this implementation is the same as the original reference cdb
 * implementation.  The MMAP version is compiled in if the HAVE_MMAP
 * preprocessor define is defined - this should be set in the system
 * specific os.h file.
 *
 */


#include "../exim.h"
#include "lf_functions.h"

#ifdef HAVE_MMAP
#  include <sys/mman.h>
/* Not all implementations declare MAP_FAILED */
#  ifndef MAP_FAILED
#    define MAP_FAILED ((void *) -1)
#  endif /* MAP_FAILED */
#endif /* HAVE_MMAP */


#define CDB_HASH_SPLIT 256     /* num pieces the hash table is split into */
#define CDB_HASH_MASK  255     /* mask to and off split value */
#define CDB_HASH_ENTRY 8       /* how big each offset it */
#define CDB_HASH_TABLE (CDB_HASH_SPLIT * CDB_HASH_ENTRY)

/* State information for cdb databases that are open NB while the db
 * is open its contents will not change (cdb dbs are normally updated
 * atomically by renaming).  However the lifetime of one of these
 * state structures should be limited - ie a long running daemon
 * that opens one may hit problems....
 */

struct cdb_state {
  int     fileno;
  off_t   filelen;
  uschar *cdb_map;
  uschar *cdb_offsets;
};

/* 32 bit unsigned type - this is an int on all modern machines */
typedef unsigned int uint32;

/*
 * cdb_hash()
 * Internal function to make hash value */

static uint32
cdb_hash(const uschar *buf, unsigned int len)
{
  uint32 h;

  h = 5381;
  while (len) {
    --len;
    h += (h << 5);
    h ^= (uint32) *buf++;
  }
  return h;
}

/*
 * cdb_bread()
 * Internal function to read len bytes from disk, coping with oddities */

static int
cdb_bread(int fd,
         uschar *buf,
         int len)
{
  int r;
  while (len > 0) {
    do
      r = Uread(fd,buf,len);
    while ((r == -1) && (errno == EINTR));
    if (r == -1) return -1;
    if (r == 0) { errno = EIO; return -1; }
    buf += r;
    len -= r;
  }
  return 0;
}

/*
 * cdb_bread()
 * Internal function to parse 4 byte number (endian independent) */

static uint32
cdb_unpack(uschar *buf)
{
  uint32 num;
  num =  buf[3]; num <<= 8;
  num += buf[2]; num <<= 8;
  num += buf[1]; num <<= 8;
  num += buf[0];
  return num;
}

static void cdb_close(void *handle);

static void *
cdb_open(uschar *filename,
         uschar **errmsg)
{
  int fileno;
  struct cdb_state *cdbp;
  struct stat statbuf;
  void * mapbuf;

  fileno = Uopen(filename, O_RDONLY, 0);
  if (fileno == -1) {
    int save_errno = errno;
    *errmsg = string_open_failed(errno, "%s for cdb lookup", filename);
    errno = save_errno;
    return NULL;
  }

  if (fstat(fileno, &statbuf) == 0) {
    /* If this is a valid file, then it *must* be at least
     * CDB_HASH_TABLE bytes long */
    if (statbuf.st_size < CDB_HASH_TABLE) {
      int save_errno = errno;
      *errmsg = string_open_failed(errno,
                                  "%s too short for cdb lookup",
                                  filename);
      errno = save_errno;
      return NULL;
    }
  } else {
    int save_errno = errno;
    *errmsg = string_open_failed(errno,
                                "fstat(%s) failed - cannot do cdb lookup",
                                filename);
    errno = save_errno;
    return NULL;
  }

  /* Having got a file open we need the structure to put things in */
  cdbp = store_get(sizeof(struct cdb_state));
  /* store_get() does not return if memory was not available... */
  /* preload the structure.... */
  cdbp->fileno = fileno;
  cdbp->filelen = statbuf.st_size;
  cdbp->cdb_map = NULL;
  cdbp->cdb_offsets = NULL;

  /* if we are allowed to we use mmap here.... */
#ifdef HAVE_MMAP
  mapbuf = mmap(NULL,
               statbuf.st_size,
               PROT_READ,
               MAP_SHARED,
               fileno,
               0);
  if (mapbuf != MAP_FAILED) {
    /* We have an mmap-ed section.  Now we can just use it */
    cdbp->cdb_map = mapbuf;
    /* The offsets can be set to the same value since they should
     * effectively be cached as well
     */
    cdbp->cdb_offsets = mapbuf;

    /* Now return the state struct */
    return(cdbp);
  } else {
    /* If we got here the map failed.  Basically we can ignore
     * this since we fall back to slower methods....
     * However lets debug log it...
     */
    DEBUG(D_lookup) debug_printf("cdb mmap failed - %d\n", errno);
  }
#endif /* HAVE_MMAP */

  /* In this case we have either not got MMAP allowed, or it failed */

  /* get a buffer to stash the basic offsets in - this should speed
   * things up a lot - especially on multiple lookups */
  cdbp->cdb_offsets = store_get(CDB_HASH_TABLE);

  /* now fill the buffer up... */
  if (cdb_bread(fileno, cdbp->cdb_offsets, CDB_HASH_TABLE) == -1) {
    /* read of hash table failed, oh dear, oh.....
     * time to give up I think....
     * call the close routine (deallocs the memory), and return NULL */
    *errmsg = string_open_failed(errno,
                                "cannot read header from %s for cdb lookup",
                                filename);
    cdb_close(cdbp);
    return NULL;
  }

  /* Everything else done - return the cache structure */
  return cdbp;
}



/*************************************************
*             Check entry point                  *
*************************************************/

static BOOL
cdb_check(void *handle,
         uschar *filename,
         int modemask,
         uid_t *owners,
         gid_t *owngroups,
         uschar **errmsg)
{
  struct cdb_state * cdbp = handle;
  return lf_check_file(cdbp->fileno,
                       filename,
                       S_IFREG,
                       modemask,
                       owners,
                       owngroups,
                       "cdb",
                       errmsg) == 0;
}



/*************************************************
*              Find entry point                  *
*************************************************/

static int
cdb_find(void *handle,
        uschar *filename,
        const uschar *keystring,
        int  key_len,
        uschar **result,
        uschar **errmsg,
        uint *do_cache)
{
struct cdb_state * cdbp = handle;
uint32 item_key_len,
item_dat_len,
key_hash,
item_hash,
item_posn,
cur_offset,
end_offset,
hash_offset_entry,
hash_offset,
hash_offlen,
hash_slotnm;
int loop;

/* Keep picky compilers happy */
do_cache = do_cache;

key_hash = cdb_hash(keystring, key_len);

hash_offset_entry = CDB_HASH_ENTRY * (key_hash & CDB_HASH_MASK);
hash_offset = cdb_unpack(cdbp->cdb_offsets + hash_offset_entry);
hash_offlen = cdb_unpack(cdbp->cdb_offsets + hash_offset_entry + 4);

/* If the offset length is zero this key cannot be in the file */

if (hash_offlen == 0)
  return FAIL;

hash_slotnm = (key_hash >> 8) % hash_offlen;

/* check to ensure that the file is not corrupt
 * if the hash_offset + (hash_offlen * CDB_HASH_ENTRY) is longer
 * than the file, then we have problems.... */

if ((hash_offset + (hash_offlen * CDB_HASH_ENTRY)) > cdbp->filelen)
  {
  *errmsg = string_sprintf("cdb: corrupt cdb file %s (too short)",
		      filename);
  DEBUG(D_lookup) debug_printf("%s\n", *errmsg);
  return DEFER;
  }

cur_offset = hash_offset + (hash_slotnm * CDB_HASH_ENTRY);
end_offset = hash_offset + (hash_offlen * CDB_HASH_ENTRY);

/* if we are allowed to we use mmap here.... */

#ifdef HAVE_MMAP
/* make sure the mmap was OK */
if (cdbp->cdb_map != NULL)
  {
  uschar * cur_pos = cur_offset + cdbp->cdb_map;
  uschar * end_pos = end_offset + cdbp->cdb_map;

  for (loop = 0; (loop < hash_offlen); ++loop)
    {
    item_hash = cdb_unpack(cur_pos);
    cur_pos += 4;
    item_posn = cdb_unpack(cur_pos);
    cur_pos += 4;

    /* if the position is zero then we have a definite miss */

    if (item_posn == 0)
      return FAIL;

    if (item_hash == key_hash)
      {					/* matching hash value */
      uschar * item_ptr = cdbp->cdb_map + item_posn;

      item_key_len = cdb_unpack(item_ptr);
      item_ptr += 4;
      item_dat_len = cdb_unpack(item_ptr);
      item_ptr += 4;

      /* check key length matches */

      if (item_key_len == key_len)
	{
	 /* finally check if key matches */
	 if (Ustrncmp(keystring, item_ptr, key_len) == 0)
	   {
	   /* we have a match....  * make item_ptr point to data */

	   item_ptr += item_key_len;

	   /* ... and the returned result */

	   *result = store_get(item_dat_len + 1);
	   memcpy(*result, item_ptr, item_dat_len);
	   (*result)[item_dat_len] = 0;
	   return OK;
	   }
	}
      }
    /* handle warp round of table */
    if (cur_pos == end_pos)
    cur_pos = cdbp->cdb_map + hash_offset;
    }
  /* looks like we failed... */
  return FAIL;
  }

#endif /* HAVE_MMAP */

for (loop = 0; (loop < hash_offlen); ++loop)
  {
  uschar packbuf[8];

  if (lseek(cdbp->fileno, (off_t) cur_offset, SEEK_SET) == -1) return DEFER;
  if (cdb_bread(cdbp->fileno, packbuf, 8) == -1) return DEFER;

  item_hash = cdb_unpack(packbuf);
  item_posn = cdb_unpack(packbuf + 4);

  /* if the position is zero then we have a definite miss */

  if (item_posn == 0)
    return FAIL;

  if (item_hash == key_hash)
    {						/* matching hash value */
    if (lseek(cdbp->fileno, (off_t) item_posn, SEEK_SET) == -1) return DEFER;
    if (cdb_bread(cdbp->fileno, packbuf, 8) == -1) return DEFER;

    item_key_len = cdb_unpack(packbuf);

    /* check key length matches */

    if (item_key_len == key_len)
      {					/* finally check if key matches */
      uschar * item_key = store_get(key_len);

      if (cdb_bread(cdbp->fileno, item_key, key_len) == -1) return DEFER;
      if (Ustrncmp(keystring, item_key, key_len) == 0) {

       /* Reclaim some store */
       store_reset(item_key);

       /* matches - get data length */
       item_dat_len = cdb_unpack(packbuf + 4);

       /* then we build a new result string.  We know we have enough
       memory so disable Coverity errors about the tainted item_dat_ken */

       *result = store_get(item_dat_len + 1);
       /* coverity[tainted_data] */
       if (cdb_bread(cdbp->fileno, *result, item_dat_len) == -1)
	 return DEFER;

       /* coverity[tainted_data] */
       (*result)[item_dat_len] = 0;
       return OK;
      }
      /* Reclaim some store */
      store_reset(item_key);
      }
    }
  cur_offset += 8;

  /* handle warp round of table */
  if (cur_offset == end_offset)
  cur_offset = hash_offset;
  }
return FAIL;
}



/*************************************************
*              Close entry point                 *
*************************************************/

/* See local README for interface description */

static void
cdb_close(void *handle)
{
struct cdb_state * cdbp = handle;

#ifdef HAVE_MMAP
 if (cdbp->cdb_map) {
   munmap(CS cdbp->cdb_map, cdbp->filelen);
   if (cdbp->cdb_map == cdbp->cdb_offsets)
     cdbp->cdb_offsets = NULL;
 }
#endif /* HAVE_MMAP */

 (void)close(cdbp->fileno);
}



/*************************************************
*         Version reporting entry point          *
*************************************************/

/* See local README for interface description. */

#include "../version.h"

void
cdb_version_report(FILE *f)
{
#ifdef DYNLOOKUP
fprintf(f, "Library version: CDB: Exim version %s\n", EXIM_VERSION_STR);
#endif
}


lookup_info cdb_lookup_info = {
  US"cdb",                       /* lookup name */
  lookup_absfile,                /* uses absolute file name */
  cdb_open,                      /* open function */
  cdb_check,                     /* check function */
  cdb_find,                      /* find function */
  cdb_close,                     /* close function */
  NULL,                          /* no tidy function */
  NULL,                          /* no quoting function */
  cdb_version_report             /* version reporting */
};

#ifdef DYNLOOKUP
#define cdb_lookup_module_info _lookup_module_info
#endif

static lookup_info *_lookup_list[] = { &cdb_lookup_info };
lookup_module_info cdb_lookup_module_info = { LOOKUP_MODULE_INFO_MAGIC, _lookup_list, 1 };

/* End of lookups/cdb.c */
