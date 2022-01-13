/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Andrew Colin Kissa <andrew@topdog.za.net> 2016 */
/* Copyright (c) University of Cambridge 2016 */
/* Copyright (c) The Exim Maintainers 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "../exim.h"
#include "queuefile.h"

/* Options specific to the appendfile transport. They must be in alphabetic
order (note that "_" comes before the lower case letters). Some of them are
stored in the publicly visible instance block - these are flagged with the
opt_public flag. */

optionlist queuefile_transport_options[] = {
  { "directory", opt_stringptr,
    (void *)offsetof(queuefile_transport_options_block, dirname) },
};


/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int queuefile_transport_options_count =
  sizeof(queuefile_transport_options) / sizeof(optionlist);


#ifdef MACRO_PREDEF

/* Dummy values */
queuefile_transport_options_block queuefile_transport_option_defaults = {0};
void queuefile_transport_init(transport_instance *tblock) {}
BOOL queuefile_transport_entry(transport_instance *tblock, address_item *addr) {return FALSE;}

#else   /*!MACRO_PREDEF*/



/* Default private options block for the appendfile transport. */

queuefile_transport_options_block queuefile_transport_option_defaults = {
  NULL,           /* dirname */
};

/*************************************************
*          Initialization entry point            *
*************************************************/

void queuefile_transport_init(transport_instance *tblock)
{
queuefile_transport_options_block *ob =
  (queuefile_transport_options_block *) tblock->options_block;

if (!ob->dirname)
  log_write(0, LOG_PANIC_DIE | LOG_CONFIG,
    "directory must be set for the %s transport", tblock->name);
}

/* This function will copy from a file to another

Arguments:
  dst        fd to write to (the destination queue file)
  src        fd to read from (the spool queue file)

Returns:       TRUE if all went well, FALSE otherwise with errno set
*/

static BOOL
copy_spool_file(int dst, int src)
{
int i, j;
uschar buffer[16384];
uschar * s;

if (lseek(src, 0, SEEK_SET) != 0)
  return FALSE;

do
  if ((j = read(src, buffer, sizeof(buffer))) > 0)
    for (s = buffer; (i = write(dst, s, j)) != j; s += i, j -= i)
      if (i < 0)
	return FALSE;
  else if (j < 0)
    return FALSE;
while (j > 0);
return TRUE;
}

/* This function performs the actual copying of the header
and data files to the destination directory

Arguments:
  tb		the transport block
  addr          address_item being processed
  dstpath	destination directory name
  sdfd          int Source directory fd
  ddfd          int Destination directory fd
  link_file     BOOL use linkat instead of data copy
  srcfd		fd for data file, or -1 for header file

Returns:       TRUE if all went well, FALSE otherwise
*/

static BOOL
copy_spool_files(transport_instance * tb, address_item * addr,
  const uschar * dstpath, int sdfd, int ddfd, BOOL link_file, int srcfd)
{
BOOL is_hdr_file = srcfd < 0;
const uschar * suffix = srcfd < 0 ? US"H" : US"D";
int dstfd;
const uschar * filename = string_sprintf("%s-%s", message_id, suffix);
const uschar * srcpath = spool_fname(US"input", message_subdir, message_id, suffix);
const uschar * s, * op;

dstpath = string_sprintf("%s/%s-%s", dstpath, message_id, suffix);

if (link_file)
  {
  DEBUG(D_transport) debug_printf("%s transport, linking %s => %s\n",
    tb->name, srcpath, dstpath);

  if (linkat(sdfd, CCS filename, ddfd, CCS filename, 0) >= 0)
    return TRUE;

  op = US"linking";
  s = dstpath;
  }
else					/* use data copy */
  {
  DEBUG(D_transport) debug_printf("%s transport, copying %s => %s\n",
    tb->name, srcpath, dstpath);

  if (  (s = dstpath,
	 (dstfd = openat(ddfd, CCS filename, O_RDWR|O_CREAT|O_EXCL, SPOOL_MODE))
	 < 0
	)
     ||    is_hdr_file
	&& (s = srcpath, (srcfd = openat(sdfd, CCS filename, O_RDONLY)) < 0)
     )
    op = US"opening";

  else
    if (s = dstpath, fchmod(dstfd, SPOOL_MODE) != 0)
      op = US"setting perms on";
    else
      if (!copy_spool_file(dstfd, srcfd))
	op = US"creating";
      else
	return TRUE;
  }

addr->basic_errno = errno;
addr->message = string_sprintf("%s transport %s file: %s failed with error: %s",
  tb->name, op, s, strerror(errno));
addr->transport_return = DEFER;
return FALSE;
}

/*************************************************
*              Main entry point                  *
*************************************************/

/* This transport always returns FALSE, indicating that the status in
the first address is the status for all addresses in a batch. */

BOOL
queuefile_transport_entry(transport_instance * tblock, address_item * addr)
{
queuefile_transport_options_block * ob =
  (queuefile_transport_options_block *) tblock->options_block;
BOOL can_link;
uschar * sourcedir = spool_dname(US"input", message_subdir);
uschar * s, * dstdir;
struct stat dstatbuf, sstatbuf;
int ddfd = -1, sdfd = -1;

DEBUG(D_transport)
  debug_printf("%s transport entered\n", tblock->name);

#ifndef O_DIRECTORY
# define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
# define O_NOFOLLOW 0
#endif

if (!(dstdir = expand_string(ob->dirname)))
  {
  addr->message = string_sprintf("%s transport: failed to expand dirname option",
    tblock->name);
  addr->transport_return = DEFER;
  return FALSE;
  }
if (*dstdir != '/')
  {
  addr->transport_return = PANIC;
  addr->message = string_sprintf("%s transport directory: "
    "%s is not absolute", tblock->name, dstdir);
  return FALSE;
  }

/* Open the source and destination directories and check if they are
on the same filesystem, so we can hard-link files rather than copying. */

if (  (s = dstdir,
       (ddfd = Uopen(s, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0)) < 0)
   || (s = sourcedir,
       (sdfd = Uopen(sourcedir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0)) < 0)
   )
  {
  addr->transport_return = PANIC;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport accessing directory: %s "
    "failed with error: %s", tblock->name, s, strerror(errno));
  if (ddfd >= 0) (void) close(ddfd);
  return FALSE;
  }

if (  (s = dstdir,    fstat(ddfd, &dstatbuf) < 0)
   || (s = sourcedir, fstat(sdfd, &sstatbuf) < 0)
   )
  {
  addr->transport_return = PANIC;
  addr->basic_errno = errno;
  addr->message = string_sprintf("%s transport fstat on directory fd: "
    "%s failed with error: %s", tblock->name, s, strerror(errno));
  goto RETURN;
  }
can_link = (dstatbuf.st_dev == sstatbuf.st_dev);

if (f.dont_deliver)
  {
  DEBUG(D_transport)
    debug_printf("*** delivery by %s transport bypassed by -N option\n",
      tblock->name);
  addr->transport_return = OK;
  goto RETURN;
  }

/* Link or copy the header and data spool files */

DEBUG(D_transport)
  debug_printf("%s transport, copying header file\n", tblock->name);

if (!copy_spool_files(tblock, addr, dstdir, sdfd, ddfd, can_link, -1))
  goto RETURN;

DEBUG(D_transport)
  debug_printf("%s transport, copying data file\n", tblock->name);

if (!copy_spool_files(tblock, addr, dstdir, sdfd, ddfd, can_link,
	deliver_datafile))
  {
  DEBUG(D_transport)
    debug_printf("%s transport, copying data file failed, "
      "unlinking the header file\n", tblock->name);
  Uunlink(string_sprintf("%s/%s-H", dstdir, message_id));
  goto RETURN;
  }

DEBUG(D_transport)
  debug_printf("%s transport succeeded\n", tblock->name);

addr->transport_return = OK;

RETURN:
if (ddfd >= 0) (void) close(ddfd);
if (sdfd >= 0) (void) close(sdfd);

/* A return of FALSE means that if there was an error, a common error was
put in the first address of a batch. */
return FALSE;
}

#endif /*!MACRO_PREDEF*/
