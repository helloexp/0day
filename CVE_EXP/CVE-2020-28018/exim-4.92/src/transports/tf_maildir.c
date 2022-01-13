/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions in support of the use of maildirsize files for handling quotas in
maildir directories. Some of the rules are a bit baroque:

http://www.inter7.com/courierimap/README.maildirquota.html

We try to follow most of that, except that the directories to skip for quota
calculations are not hard wired in, but are supplied as a regex. */


#include "../exim.h"
#include "appendfile.h"
#include "tf_maildir.h"

#define MAX_FILE_SIZE  5120



/*************************************************
*      Ensure maildir directories exist          *
*************************************************/

/* This function is called at the start of a maildir delivery, to ensure that
all the relevant directories exist. It also creates a maildirfolder file if the
base directory matches a given pattern.

Argument:
  path              the base directory name
  addr              the address item (for setting an error message)
  create_directory  true if we are allowed to create missing directories
  dirmode           the mode for created directories
  maildirfolder_create_regex
                    the pattern to match for maildirfolder creation

Returns:            TRUE on success; FALSE on failure
*/

BOOL maildir_ensure_directories(uschar *path, address_item *addr,
  BOOL create_directory, int dirmode, uschar *maildirfolder_create_regex)
{
int i;
struct stat statbuf;
const char *subdirs[] = { "/tmp", "/new", "/cur" };

DEBUG(D_transport)
  debug_printf("ensuring maildir directories exist in %s\n", path);

/* First ensure that the path we have is a directory; if it does not exist,
create it. Then make sure the tmp, new & cur subdirs of the maildir are
there. If not, fail. This aborts the delivery (even though the cur subdir is
not actually needed for delivery). Handle all 4 directory tests/creates in a
loop so that code can be shared. */

for (i = 0; i < 4; i++)
  {
  int j;
  const uschar *dir, *mdir;

  if (i == 0)
    {
    mdir = CUS"";
    dir = path;
    }
  else
    {
    mdir = CUS subdirs[i-1];
    dir = mdir + 1;
    }

  /* Check an existing path is a directory. This is inside a loop because
  there is a potential race condition when creating the directory - some
  other process may get there first. Give up after trying several times,
  though. */

  for (j = 0; j < 10; j++)
    {
    if (Ustat(dir, &statbuf) == 0)
      {
      if (S_ISDIR(statbuf.st_mode)) break;   /* out of the race loop */
      addr->message = string_sprintf("%s%s is not a directory", path,
        mdir);
      addr->basic_errno = ERRNO_NOTDIRECTORY;
      return FALSE;
      }

    /* Try to make if non-existent and configured to do so */

    if (errno == ENOENT && create_directory)
      {
      if (!directory_make(NULL, dir, dirmode, FALSE))
        {
        if (errno == EEXIST) continue;     /* repeat the race loop */
        addr->message = string_sprintf("cannot create %s%s", path, mdir);
        addr->basic_errno = errno;
        return FALSE;
        }
      DEBUG(D_transport)
        debug_printf("created directory %s%s\n", path, mdir);
      break;   /* out of the race loop */
      }

    /* stat() error other than ENOENT, or ENOENT and not creatable */

    addr->message = string_sprintf("stat() error for %s%s: %s", path, mdir,
      strerror(errno));
    addr->basic_errno = errno;
    return FALSE;
    }

  /* If we went round the loop 10 times, the directory was flickering in
  and out of existence like someone in a malfunctioning Star Trek
  transporter. */

  if (j >= 10)
    {
    addr->message = string_sprintf("existence of %s%s unclear\n", path,
      mdir);
    addr->basic_errno = errno;
    addr->special_action = SPECIAL_FREEZE;
    return FALSE;
    }

  /* First time through the directories loop, cd to the main directory */

  if (i == 0 && Uchdir(path) != 0)
    {
    addr->message = string_sprintf ("cannot chdir to %s", path);
    addr->basic_errno = errno;
    return FALSE;
    }
  }

/* If the basic path matches maildirfolder_create_regex, we are dealing with
a subfolder, and should ensure that a maildirfolder file exists. */

if (maildirfolder_create_regex != NULL)
  {
  const uschar *error;
  int offset;
  const pcre *regex;

  DEBUG(D_transport) debug_printf("checking for maildirfolder requirement\n");

  regex = pcre_compile(CS maildirfolder_create_regex, PCRE_COPT,
    (const char **)&error, &offset, NULL);

  if (regex == NULL)
    {
    addr->message = string_sprintf("appendfile: regular expression "
      "error: %s at offset %d while compiling %s", error, offset,
      maildirfolder_create_regex);
    return FALSE;
    }

  if (pcre_exec(regex, NULL, CS path, Ustrlen(path), 0, 0, NULL, 0) >= 0)
    {
    uschar *fname = string_sprintf("%s/maildirfolder", path);
    if (Ustat(fname, &statbuf) == 0)
      {
      DEBUG(D_transport) debug_printf("maildirfolder already exists\n");
      }
    else
      {
      int fd = Uopen(fname, O_WRONLY|O_APPEND|O_CREAT, 0600);
      if (fd < 0)
        {
        addr->message = string_sprintf("appendfile: failed to create "
          "maildirfolder file in %s directory: %s", path, strerror(errno));
        return FALSE;
        }
      (void)close(fd);
      DEBUG(D_transport) debug_printf("created maildirfolder file\n");
      }
    }
  else
    {
    DEBUG(D_transport) debug_printf("maildirfolder file not required\n");
    }
  }

return TRUE;   /* Everything exists that should exist */
}




/*************************************************
*       Update maildirsizefile for new file      *
*************************************************/

/* This function is called to add a new line to the file, recording the length
of the newly added message. There isn't much we can do on failure...

Arguments:
  fd           the open file descriptor
  size         the size of the message

Returns:       nothing
*/

void
maildir_record_length(int fd, int size)
{
int len;
uschar buffer[256];
sprintf(CS buffer, "%d 1\n", size);
len = Ustrlen(buffer);
if (lseek(fd, 0, SEEK_END) >= 0)
  {
  len = write(fd, buffer, len);
  DEBUG(D_transport)
    debug_printf("added '%.*s' to maildirsize file\n", len-1, buffer);
  }
}



/*************************************************
*          Find the size of a maildir            *
*************************************************/

/* This function is called when we have to recalculate the size of a maildir by
scanning all the files and directories therein. There are rules and conventions
about which files or directories are included. We support this by the use of a
regex to match directories that are to be included.

Maildirs can only be one level deep. However, this function recurses, so it
might cope with deeper nestings. We use the existing check_dir_size() function
to add up the sizes of the files in a directory that contains messages.

The function returns the most recent timestamp encountered. It can also be run
in a dummy mode in which it does not scan for sizes, but just returns the
timestamp.

Arguments:
  path            the path to the maildir
  filecount       where to store the count of messages
  latest          where to store the latest timestamp encountered
  regex           a regex for getting files sizes from file names
  dir_regex       a regex for matching directories to be included
  timestamp_only  don't actually compute any sizes

Returns:      the sum of the sizes of the messages
*/

off_t
maildir_compute_size(uschar *path, int *filecount, time_t *latest,
  const pcre *regex, const pcre *dir_regex, BOOL timestamp_only)
{
DIR *dir;
off_t sum = 0;
struct dirent *ent;
struct stat statbuf;

dir = opendir(CS path);
if (dir == NULL) return 0;

while ((ent = readdir(dir)) != NULL)
  {
  uschar *name = US ent->d_name;
  uschar buffer[1024];

  if (Ustrcmp(name, ".") == 0 || Ustrcmp(name, "..") == 0) continue;

  /* We are normally supplied with a regex for choosing which directories to
  scan. We do the regex match first, because that avoids a stat() for names
  we aren't interested in. */

  if (dir_regex != NULL &&
      pcre_exec(dir_regex, NULL, CS name, Ustrlen(name), 0, 0, NULL, 0) < 0)
    {
    DEBUG(D_transport)
      debug_printf("skipping %s/%s: dir_regex does not match\n", path, name);
    continue;
    }

  /* The name is OK; stat it. */

  if (!string_format(buffer, sizeof(buffer), "%s/%s", path, name))
    {
    DEBUG(D_transport)
      debug_printf("maildir_compute_size: name too long: dir=%s name=%s\n",
        path, name);
    continue;
    }

  if (Ustat(buffer, &statbuf) < 0)
    {
    DEBUG(D_transport)
      debug_printf("maildir_compute_size: stat error %d for %s: %s\n", errno,
        buffer, strerror(errno));
    continue;
    }

  if ((statbuf.st_mode & S_IFMT) != S_IFDIR)
    {
    DEBUG(D_transport)
      debug_printf("skipping %s/%s: not a directory\n", path, name);
    continue;
    }

  /* Keep the latest timestamp encountered */

  if (statbuf.st_mtime > *latest) *latest = statbuf.st_mtime;

  /* If this is a maildir folder, call this function recursively. */

  if (name[0] == '.')
    {
    sum += maildir_compute_size(buffer, filecount, latest, regex, dir_regex,
      timestamp_only);
    }

  /* Otherwise it must be a folder that contains messages (e.g. new or cur), so
  we need to get its size, unless all we are interested in is the timestamp. */

  else if (!timestamp_only)
    {
    sum += check_dir_size(buffer, filecount, regex);
    }
  }

closedir(dir);
DEBUG(D_transport)
  {
  if (timestamp_only)
    debug_printf("maildir_compute_size (timestamp_only): %ld\n",
    (long int) *latest);
  else
    debug_printf("maildir_compute_size: path=%s\n  sum=" OFF_T_FMT
      " filecount=%d timestamp=%ld\n",
      path, sum, *filecount, (long int) *latest);
  }
return sum;
}



/*************************************************
*        Create or update maildirsizefile        *
*************************************************/

/* This function is called before a delivery if the option to use
maildirsizefile is enabled. Its function is to create the file if it does not
exist, or to update it if that is necessary.

The logic in this function follows the rules that are described in

  http://www.inter7.com/courierimap/README.maildirquota.html

Or, at least, it is supposed to!

Arguments:
  path             the path to the maildir directory; this is already backed-up
                     to the parent if the delivery directory is a maildirfolder
  ob               the appendfile options block
  regex            a compiled regex for getting a file's size from its name
  dir_regex        a compiled regex for selecting maildir directories
  returned_size    where to return the current size of the maildir, even if
                     the maildirsizefile is removed because of a race

Returns:           >=0  a file descriptor for an open maildirsize file
                   -1   there was an error opening or accessing the file
                   -2   the file was removed because of a race
*/

int
maildir_ensure_sizefile(uschar *path, appendfile_transport_options_block *ob,
  const pcre *regex, const pcre *dir_regex, off_t *returned_size,
  int *returned_filecount)
{
int count, fd;
off_t cached_quota = 0;
int cached_quota_filecount = 0;
int filecount = 0;
int linecount = 0;
off_t size = 0;
uschar *filename;
uschar buffer[MAX_FILE_SIZE];
uschar *ptr = buffer;
uschar *endptr;

/* Try a few times to open or create the file, in case another process is doing
the same thing. */

filename = string_sprintf("%s/maildirsize", path);

DEBUG(D_transport) debug_printf("looking for maildirsize in %s\n", path);
fd = Uopen(filename, O_RDWR|O_APPEND, ob->mode ? ob->mode : 0600);
if (fd < 0)
  {
  if (errno != ENOENT) return -1;
  DEBUG(D_transport)
    debug_printf("%s does not exist: recalculating\n", filename);
  goto RECALCULATE;
  }

/* The file has been successfully opened. Check that the cached quota value is
still correct, and that the size of the file is still small enough. If so,
compute the maildir size from the file. */

count = read(fd, buffer, sizeof(buffer));
if (count >= sizeof(buffer))
  {
  DEBUG(D_transport)
    debug_printf("maildirsize file too big (%d): recalculating\n", count);
  goto RECALCULATE;
  }
buffer[count] = 0;   /* Ensure string terminated */

/* Read the quota parameters from the first line of the data. */

DEBUG(D_transport)
  debug_printf("reading quota parameters from maildirsize data\n");

for (;;)
  {
  off_t n = (off_t)Ustrtod(ptr, &endptr);

  /* Only two data items are currently defined; ignore any others that
  may be present. The spec is for a number followed by a letter. Anything
  else we reject and recalculate. */

  if (*endptr == 'S') cached_quota = n;
    else if (*endptr == 'C') cached_quota_filecount = (int)n;
  if (!isalpha(*endptr++))
    {
    DEBUG(D_transport)
      debug_printf("quota parameter number not followed by letter in "
        "\"%.*s\": recalculating maildirsize\n", (int)(endptr - buffer),
        buffer);
    goto RECALCULATE;
    }
  if (*endptr == '\n' || *endptr == 0) break;
  if (*endptr++ != ',')
    {
    DEBUG(D_transport)
      debug_printf("quota parameter not followed by comma in "
        "\"%.*s\": recalculating maildirsize\n", (int)(endptr - buffer),
        buffer);
    goto RECALCULATE;
    }
  ptr = endptr;
  }

/* Check the cached values against the current settings */

if (cached_quota != ob->quota_value ||
    cached_quota_filecount != ob->quota_filecount_value)
  {
  DEBUG(D_transport)
    debug_printf("cached quota is out of date: recalculating\n"
      "  quota=" OFF_T_FMT " cached_quota=" OFF_T_FMT " filecount_quota=%d "
      "cached_quota_filecount=%d\n", ob->quota_value,
      cached_quota, ob->quota_filecount_value, cached_quota_filecount);
  goto RECALCULATE;
  }

/* Quota values agree; parse the rest of the data to get the sizes. At this
stage, *endptr points either to 0 or to '\n'.  */

DEBUG(D_transport)
  debug_printf("computing maildir size from maildirsize data\n");

while (*endptr++ == '\n')
  {
  if (*endptr == 0) break;
  linecount++;
  ptr = endptr;
  size += (off_t)Ustrtod(ptr, &endptr);
  if (*endptr != ' ') break;
  ptr = endptr + 1;
  filecount += Ustrtol(ptr, &endptr, 10);
  }

/* If *endptr is zero, we have successfully parsed the file, and we now have
the size of the mailbox as cached in the file. The "rules" say that if this
value indicates that the mailbox is over quota, we must recalculate if there is
more than one entry in the file, or if the file is older than 15 minutes. Also,
just in case there are weird values in the file, recalculate if either of the
values is negative. */

if (*endptr == 0)
  {
  if (size < 0 || filecount < 0)
    {
    DEBUG(D_transport) debug_printf("negative value in maildirsize "
      "(size=" OFF_T_FMT " count=%d): recalculating\n", size, filecount);
    goto RECALCULATE;
    }

  if (ob->quota_value > 0 &&
      (size + (ob->quota_is_inclusive? message_size : 0) > ob->quota_value ||
        (ob->quota_filecount_value > 0 &&
          filecount + (ob->quota_is_inclusive ? 1:0) >
            ob->quota_filecount_value)
      ))
    {
    struct stat statbuf;
    if (linecount > 1)
      {
      DEBUG(D_transport) debug_printf("over quota and maildirsize has "
        "more than 1 entry: recalculating\n");
      goto RECALCULATE;
      }

    if (fstat(fd, &statbuf) < 0) goto RECALCULATE;  /* Should never occur */

    if (time(NULL) - statbuf.st_mtime > 15*60)
      {
      DEBUG(D_transport) debug_printf("over quota and maildirsize is older "
        "than 15 minutes: recalculating\n");
      goto RECALCULATE;
      }
    }
  }


/* If *endptr is not zero, there was a syntax error in the file. */

else
  {
  int len;
  time_t old_latest, new_latest;
  uschar *tempname;
  struct timeval tv;

  DEBUG(D_transport)
    {
    uschar *p = endptr;
    while (p > buffer && p[-1] != '\n') p--;
    endptr[1] = 0;

    debug_printf("error in maildirsizefile: unexpected character %d in "
      "line %d (starting '%s'): recalculating\n",
      *endptr, linecount + 1, string_printing(p));
    }

  /* Either there is no file, or the quota value has changed, or the file has
  got too big, or there was some format error in the file. Recalculate the size
  and write new contents to a temporary file; then rename it. After any
  error, just return -1 as the file descriptor. */

  RECALCULATE:

  if (fd >= 0) (void)close(fd);
  old_latest = 0;
  filecount = 0;
  size = maildir_compute_size(path, &filecount, &old_latest, regex, dir_regex,
    FALSE);

  (void)gettimeofday(&tv, NULL);
  tempname = string_sprintf("%s/tmp/" TIME_T_FMT ".H%luP%lu.%s",
    path, tv.tv_sec, tv.tv_usec, (long unsigned) getpid(), primary_hostname);

  fd = Uopen(tempname, O_RDWR|O_CREAT|O_EXCL, ob->mode ? ob->mode : 0600);
  if (fd >= 0)
    {
    (void)sprintf(CS buffer, OFF_T_FMT "S,%dC\n" OFF_T_FMT " %d\n",
      ob->quota_value, ob->quota_filecount_value, size, filecount);
    len = Ustrlen(buffer);
    if (write(fd, buffer, len) != len || Urename(tempname, filename) < 0)
      {
      (void)close(fd);
      fd = -1;
      }
    }

  /* If any of the directories have been modified since the last timestamp we
  saw, we have to junk this maildirsize file. */

  DEBUG(D_transport) debug_printf("checking subdirectory timestamps\n");
  new_latest = 0;
  (void)maildir_compute_size(path, NULL, &new_latest , NULL, dir_regex, TRUE);
  if (new_latest > old_latest)
    {
    DEBUG(D_transport) debug_printf("abandoning maildirsize because of "
      "a later subdirectory modification\n");
    (void)Uunlink(filename);
    (void)close(fd);
    fd = -2;
    }
  }

/* Return the sizes and the file descriptor, if any */

DEBUG(D_transport) debug_printf("returning maildir size=" OFF_T_FMT
  " filecount=%d\n", size, filecount);
*returned_size = size;
*returned_filecount = filecount;
return fd;
}

/* End of tf_maildir.c */
