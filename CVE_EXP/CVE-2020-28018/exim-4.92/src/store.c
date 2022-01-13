/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Exim gets and frees all its store through these functions. In the original
implementation there was a lot of mallocing and freeing of small bits of store.
The philosophy has now changed to a scheme which includes the concept of
"stacking pools" of store. For the short-lived processes, there isn't any real
need to do any garbage collection, but the stack concept allows quick resetting
in places where this seems sensible.

Obviously the long-running processes (the daemon, the queue runner, and eximon)
must take care not to eat store.

The following different types of store are recognized:

. Long-lived, large blocks: This is implemented by retaining the original
  malloc/free functions, and it used for permanent working buffers and for
  getting blocks to cut up for the other types.

. Long-lived, small blocks: This is used for blocks that have to survive until
  the process exits. It is implemented as a stacking pool (POOL_PERM). This is
  functionally the same as store_malloc(), except that the store can't be
  freed, but I expect it to be more efficient for handling small blocks.

. Short-lived, short blocks: Most of the dynamic store falls into this
  category. It is implemented as a stacking pool (POOL_MAIN) which is reset
  after accepting a message when multiple messages are received by a single
  process. Resetting happens at some other times as well, usually fairly
  locally after some specific processing that needs working store.

. There is a separate pool (POOL_SEARCH) that is used only for lookup storage.
  This means it can be freed when search_tidyup() is called to close down all
  the lookup caching.
*/


#include "exim.h"
/* keep config.h before memcheck.h, for NVALGRIND */
#include "config.h"

#include "memcheck.h"


/* We need to know how to align blocks of data for general use. I'm not sure
how to get an alignment factor in general. In the current world, a value of 8
is probably right, and this is sizeof(double) on some systems and sizeof(void
*) on others, so take the larger of those. Since everything in this expression
is a constant, the compiler should optimize it to a simple constant wherever it
appears (I checked that gcc does do this). */

#define alignment \
  ((sizeof(void *) > sizeof(double))? sizeof(void *) : sizeof(double))

/* Size of block to get from malloc to carve up into smaller ones. This
must be a multiple of the alignment. We assume that 8192 is going to be
suitably aligned. */

#define STORE_BLOCK_SIZE 8192

/* store_reset() will not free the following block if the last used block has
less than this much left in it. */

#define STOREPOOL_MIN_SIZE 256

/* Structure describing the beginning of each big block. */

typedef struct storeblock {
  struct storeblock *next;
  size_t length;
} storeblock;

/* Just in case we find ourselves on a system where the structure above has a
length that is not a multiple of the alignment, set up a macro for the padded
length. */

#define ALIGNED_SIZEOF_STOREBLOCK \
  (((sizeof(storeblock) + alignment - 1) / alignment) * alignment)

/* Variables holding data for the local pools of store. The current pool number
is held in store_pool, which is global so that it can be changed from outside.
Setting the initial length values to -1 forces a malloc for the first call,
even if the length is zero (which is used for getting a point to reset to). */

int store_pool = POOL_PERM;

static storeblock *chainbase[3] = { NULL, NULL, NULL };
static storeblock *current_block[3] = { NULL, NULL, NULL };
static void *next_yield[3] = { NULL, NULL, NULL };
static int yield_length[3] = { -1, -1, -1 };

/* pool_malloc holds the amount of memory used by the store pools; this goes up
and down as store is reset or released. nonpool_malloc is the total got by
malloc from other calls; this doesn't go down because it is just freed by
pointer. */

static int pool_malloc = 0;
static int nonpool_malloc = 0;

/* This variable is set by store_get() to its yield, and by store_reset() to
NULL. This enables string_cat() to optimize its store handling for very long
strings. That's why the variable is global. */

void *store_last_get[3] = { NULL, NULL, NULL };



/*************************************************
*       Get a block from the current pool        *
*************************************************/

/* Running out of store is a total disaster. This function is called via the
macro store_get(). It passes back a block of store within the current big
block, getting a new one if necessary. The address is saved in
store_last_was_get.

Arguments:
  size        amount wanted
  filename    source file from which called
  linenumber  line number in source file.

Returns:      pointer to store (panic on malloc failure)
*/

void *
store_get_3(int size, const char *filename, int linenumber)
{
/* Round up the size to a multiple of the alignment. Although this looks a
messy statement, because "alignment" is a constant expression, the compiler can
do a reasonable job of optimizing, especially if the value of "alignment" is a
power of two. I checked this with -O2, and gcc did very well, compiling it to 4
instructions on a Sparc (alignment = 8). */

if (size % alignment != 0) size += alignment - (size % alignment);

/* If there isn't room in the current block, get a new one. The minimum
size is STORE_BLOCK_SIZE, and we would expect this to be the norm, since
these functions are mostly called for small amounts of store. */

if (size > yield_length[store_pool])
  {
  int length = (size <= STORE_BLOCK_SIZE)? STORE_BLOCK_SIZE : size;
  int mlength = length + ALIGNED_SIZEOF_STOREBLOCK;
  storeblock * newblock = NULL;

  /* Sometimes store_reset() may leave a block for us; check if we can use it */

  if (  (newblock = current_block[store_pool])
     && (newblock = newblock->next)
     && newblock->length < length
     )
    {
    /* Give up on this block, because it's too small */
    store_free(newblock);
    newblock = NULL;
    }

  /* If there was no free block, get a new one */

  if (!newblock)
    {
    pool_malloc += mlength;           /* Used in pools */
    nonpool_malloc -= mlength;        /* Exclude from overall total */
    newblock = store_malloc(mlength);
    newblock->next = NULL;
    newblock->length = length;
    if (!chainbase[store_pool])
      chainbase[store_pool] = newblock;
    else
      current_block[store_pool]->next = newblock;
    }

  current_block[store_pool] = newblock;
  yield_length[store_pool] = newblock->length;
  next_yield[store_pool] =
    (void *)(CS current_block[store_pool] + ALIGNED_SIZEOF_STOREBLOCK);
  (void) VALGRIND_MAKE_MEM_NOACCESS(next_yield[store_pool], yield_length[store_pool]);
  }

/* There's (now) enough room in the current block; the yield is the next
pointer. */

store_last_get[store_pool] = next_yield[store_pool];

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifdef COMPILE_UTILITY
filename = filename;
linenumber = linenumber;
#else
DEBUG(D_memory)
  {
  if (f.running_in_test_harness)
    debug_printf("---%d Get %5d\n", store_pool, size);
  else
    debug_printf("---%d Get %6p %5d %-14s %4d\n", store_pool,
      store_last_get[store_pool], size, filename, linenumber);
  }
#endif  /* COMPILE_UTILITY */

(void) VALGRIND_MAKE_MEM_UNDEFINED(store_last_get[store_pool], size);
/* Update next pointer and number of bytes left in the current block. */

next_yield[store_pool] = (void *)(CS next_yield[store_pool] + size);
yield_length[store_pool] -= size;

return store_last_get[store_pool];
}



/*************************************************
*       Get a block from the PERM pool           *
*************************************************/

/* This is just a convenience function, useful when just a single block is to
be obtained.

Arguments:
  size        amount wanted
  filename    source file from which called
  linenumber  line number in source file.

Returns:      pointer to store (panic on malloc failure)
*/

void *
store_get_perm_3(int size, const char *filename, int linenumber)
{
void *yield;
int old_pool = store_pool;
store_pool = POOL_PERM;
yield = store_get_3(size, filename, linenumber);
store_pool = old_pool;
return yield;
}



/*************************************************
*      Extend a block if it is at the top        *
*************************************************/

/* While reading strings of unknown length, it is often the case that the
string is being read into the block at the top of the stack. If it needs to be
extended, it is more efficient just to extend the top block rather than
allocate a new block and then have to copy the data. This function is provided
for the use of string_cat(), but of course can be used elsewhere too.

Arguments:
  ptr        pointer to store block
  oldsize    current size of the block, as requested by user
  newsize    new size required
  filename   source file from which called
  linenumber line number in source file

Returns:     TRUE if the block is at the top of the stack and has been
             extended; FALSE if it isn't at the top of the stack, or cannot
             be extended
*/

BOOL
store_extend_3(void *ptr, int oldsize, int newsize, const char *filename,
  int linenumber)
{
int inc = newsize - oldsize;
int rounded_oldsize = oldsize;

if (rounded_oldsize % alignment != 0)
  rounded_oldsize += alignment - (rounded_oldsize % alignment);

if (CS ptr + rounded_oldsize != CS (next_yield[store_pool]) ||
    inc > yield_length[store_pool] + rounded_oldsize - oldsize)
  return FALSE;

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifdef COMPILE_UTILITY
filename = filename;
linenumber = linenumber;
#else
DEBUG(D_memory)
  {
  if (f.running_in_test_harness)
    debug_printf("---%d Ext %5d\n", store_pool, newsize);
  else
    debug_printf("---%d Ext %6p %5d %-14s %4d\n", store_pool, ptr, newsize,
      filename, linenumber);
  }
#endif  /* COMPILE_UTILITY */

if (newsize % alignment != 0) newsize += alignment - (newsize % alignment);
next_yield[store_pool] = CS ptr + newsize;
yield_length[store_pool] -= newsize - rounded_oldsize;
(void) VALGRIND_MAKE_MEM_UNDEFINED(ptr + oldsize, inc);
return TRUE;
}




/*************************************************
*    Back up to a previous point on the stack    *
*************************************************/

/* This function resets the next pointer, freeing any subsequent whole blocks
that are now unused. Normally it is given a pointer that was the yield of a
call to store_get, and is therefore aligned, but it may be given an offset
after such a pointer in order to release the end of a block and anything that
follows.

Arguments:
  ptr         place to back up to
  filename    source file from which called
  linenumber  line number in source file

Returns:      nothing
*/

void
store_reset_3(void *ptr, const char *filename, int linenumber)
{
storeblock * bb;
storeblock * b = current_block[store_pool];
char * bc = CS b + ALIGNED_SIZEOF_STOREBLOCK;
int newlength;

/* Last store operation was not a get */

store_last_get[store_pool] = NULL;

/* See if the place is in the current block - as it often will be. Otherwise,
search for the block in which it lies. */

if (CS ptr < bc || CS ptr > bc + b->length)
  {
  for (b = chainbase[store_pool]; b; b = b->next)
    {
    bc = CS b + ALIGNED_SIZEOF_STOREBLOCK;
    if (CS ptr >= bc && CS ptr <= bc + b->length) break;
    }
  if (!b)
    log_write(0, LOG_MAIN|LOG_PANIC_DIE, "internal error: store_reset(%p) "
      "failed: pool=%d %-14s %4d", ptr, store_pool, filename, linenumber);
  }

/* Back up, rounding to the alignment if necessary. When testing, flatten
the released memory. */

newlength = bc + b->length - CS ptr;
#ifndef COMPILE_UTILITY
if (debug_store)
  {
  assert_no_variables(ptr, newlength, filename, linenumber);
  if (f.running_in_test_harness)
    {
    (void) VALGRIND_MAKE_MEM_DEFINED(ptr, newlength);
    memset(ptr, 0xF0, newlength);
    }
  }
#endif
(void) VALGRIND_MAKE_MEM_NOACCESS(ptr, newlength);
yield_length[store_pool] = newlength - (newlength % alignment);
next_yield[store_pool] = CS ptr + (newlength % alignment);
current_block[store_pool] = b;

/* Free any subsequent block. Do NOT free the first successor, if our
current block has less than 256 bytes left. This should prevent us from
flapping memory. However, keep this block only when it has the default size. */

if (yield_length[store_pool] < STOREPOOL_MIN_SIZE &&
    b->next &&
    b->next->length == STORE_BLOCK_SIZE)
  {
  b = b->next;
#ifndef COMPILE_UTILITY
  if (debug_store)
    assert_no_variables(b, b->length + ALIGNED_SIZEOF_STOREBLOCK,
			filename, linenumber);
#endif
  (void) VALGRIND_MAKE_MEM_NOACCESS(CS b + ALIGNED_SIZEOF_STOREBLOCK,
		b->length - ALIGNED_SIZEOF_STOREBLOCK);
  }

bb = b->next;
b->next = NULL;

while ((b = bb))
  {
#ifndef COMPILE_UTILITY
  if (debug_store)
    assert_no_variables(b, b->length + ALIGNED_SIZEOF_STOREBLOCK,
			filename, linenumber);
#endif
  bb = bb->next;
  pool_malloc -= b->length + ALIGNED_SIZEOF_STOREBLOCK;
  store_free_3(b, filename, linenumber);
  }

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifdef COMPILE_UTILITY
filename = filename;
linenumber = linenumber;
#else
DEBUG(D_memory)
  {
  if (f.running_in_test_harness)
    debug_printf("---%d Rst    ** %d\n", store_pool, pool_malloc);
  else
    debug_printf("---%d Rst %6p    ** %-14s %4d %d\n", store_pool, ptr,
      filename, linenumber, pool_malloc);
  }
#endif  /* COMPILE_UTILITY */
}





/************************************************
*             Release store                     *
************************************************/

/* This function checks that the pointer it is given is the first thing in a
block, and if so, releases that block.

Arguments:
  block       block of store to consider
  filename    source file from which called
  linenumber  line number in source file

Returns:      nothing
*/

static void
store_release_3(void * block, const char * filename, int linenumber)
{
storeblock * b;

/* It will never be the first block, so no need to check that. */

for (b = chainbase[store_pool]; b; b = b->next)
  {
  storeblock * bb = b->next;
  if (bb && CS block == CS bb + ALIGNED_SIZEOF_STOREBLOCK)
    {
    b->next = bb->next;
    pool_malloc -= bb->length + ALIGNED_SIZEOF_STOREBLOCK;

    /* Cut out the debugging stuff for utilities, but stop picky compilers
    from giving warnings. */

#ifdef COMPILE_UTILITY
    filename = filename;
    linenumber = linenumber;
#else
    DEBUG(D_memory)
      if (f.running_in_test_harness)
        debug_printf("-Release       %d\n", pool_malloc);
      else
        debug_printf("-Release %6p %-20s %4d %d\n", (void *)bb, filename,
          linenumber, pool_malloc);

    if (f.running_in_test_harness)
      memset(bb, 0xF0, bb->length+ALIGNED_SIZEOF_STOREBLOCK);
#endif  /* COMPILE_UTILITY */

    free(bb);
    return;
    }
  }
}


/************************************************
*             Move store                        *
************************************************/

/* Allocate a new block big enough to expend to the given size and
copy the current data into it.  Free the old one if possible.

This function is specifically provided for use when reading very
long strings, e.g. header lines. When the string gets longer than a
complete block, it gets copied to a new block. It is helpful to free
the old block iff the previous copy of the string is at its start,
and therefore the only thing in it. Otherwise, for very long strings,
dead store can pile up somewhat disastrously. This function checks that
the pointer it is given is the first thing in a block, and that nothing
has been allocated since. If so, releases that block.

Arguments:
  block
  newsize
  len

Returns:	new location of data
*/

void *
store_newblock_3(void * block, int newsize, int len,
  const char * filename, int linenumber)
{
BOOL release_ok = store_last_get[store_pool] == block;
uschar * newtext = store_get(newsize);

memcpy(newtext, block, len);
if (release_ok) store_release_3(block, filename, linenumber);
return (void *)newtext;
}




/*************************************************
*                Malloc store                    *
*************************************************/

/* Running out of store is a total disaster for exim. Some malloc functions
do not run happily on very small sizes, nor do they document this fact. This
function is called via the macro store_malloc().

Arguments:
  size        amount of store wanted
  filename    source file from which called
  linenumber  line number in source file

Returns:      pointer to gotten store (panic on failure)
*/

void *
store_malloc_3(int size, const char *filename, int linenumber)
{
void *yield;

if (size < 16) size = 16;

if (!(yield = malloc((size_t)size)))
  log_write(0, LOG_MAIN|LOG_PANIC_DIE, "failed to malloc %d bytes of memory: "
    "called from line %d of %s", size, linenumber, filename);

nonpool_malloc += size;

/* Cut out the debugging stuff for utilities, but stop picky compilers from
giving warnings. */

#ifdef COMPILE_UTILITY
filename = filename;
linenumber = linenumber;
#else

/* If running in test harness, spend time making sure all the new store
is not filled with zeros so as to catch problems. */

if (f.running_in_test_harness)
  {
  memset(yield, 0xF0, (size_t)size);
  DEBUG(D_memory) debug_printf("--Malloc %5d %d %d\n", size, pool_malloc,
    nonpool_malloc);
  }
else
  {
  DEBUG(D_memory) debug_printf("--Malloc %6p %5d %-14s %4d %d %d\n", yield,
    size, filename, linenumber, pool_malloc, nonpool_malloc);
  }
#endif  /* COMPILE_UTILITY */

return yield;
}


/************************************************
*             Free store                        *
************************************************/

/* This function is called by the macro store_free().

Arguments:
  block       block of store to free
  filename    source file from which called
  linenumber  line number in source file

Returns:      nothing
*/

void
store_free_3(void *block, const char *filename, int linenumber)
{
#ifdef COMPILE_UTILITY
filename = filename;
linenumber = linenumber;
#else
DEBUG(D_memory)
  {
  if (f.running_in_test_harness)
    debug_printf("----Free\n");
  else
    debug_printf("----Free %6p %-20s %4d\n", block, filename, linenumber);
  }
#endif  /* COMPILE_UTILITY */
free(block);
}

/* End of store.c */
