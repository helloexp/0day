/*************************************************
*                 Exim Monitor                   *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


#include "em_hdr.h"


/* This module contains functions to do with scanning exim's
queue and displaying the data therefrom. */


/* If we are anonymizing for screen shots, define a function to anonymize
addresses. Otherwise, define a macro that does nothing. */

#ifdef ANONYMIZE
static uschar *anon(uschar *s)
{
static uschar anon_result[256];
uschar *ss = anon_result;
for (; *s != 0; s++) *ss++ = (*s == '@' || *s == '.')? *s : 'x';
*ss = 0;
return anon_result;
}
#else
#define anon(x) x
#endif


/*************************************************
*                 Static variables               *
*************************************************/

static int queue_total = 0;   /* number of items in queue */

/* Table for turning base-62 numbers into binary */

static uschar tab62[] =
          {0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0,     /* 0-9 */
           0,10,11,12,13,14,15,16,17,18,19,20,  /* A-K */
          21,22,23,24,25,26,27,28,29,30,31,32,  /* L-W */
          33,34,35, 0, 0, 0, 0, 0,              /* X-Z */
           0,36,37,38,39,40,41,42,43,44,45,46,  /* a-k */
          47,48,49,50,51,52,53,54,55,56,57,58,  /* l-w */
          59,60,61};                            /* x-z */

/* Index for quickly finding things in the ordered queue. */

static queue_item *queue_index[queue_index_size];



/*************************************************
*         Find/Create/Delete a destination       *
*************************************************/

/* If the action is dest_noop, then just return item or NULL;
if it is dest_add, then add if not present, and return item;
if it is dest_remove, remove if present and return NULL. The
address is lowercased to start with, unless it begins with
"*", which it does for error messages. */

dest_item *
find_dest(queue_item *q, uschar *name, int action, BOOL caseless)
{
dest_item *dd;
dest_item **d = &(q->destinations);

while (*d != NULL)
  {
  if ((caseless? strcmpic(name,(*d)->address) : Ustrcmp(name,(*d)->address))
        == 0)
    {
    dest_item *ddd;

    if (action != dest_remove) return *d;
    dd = *d;
    *d = dd->next;
    store_free(dd);

    /* Unset any parent pointers that were to this address */

    for (ddd = q->destinations; ddd != NULL; ddd = ddd->next)
      {
      if (ddd->parent == dd) ddd->parent = NULL;
      }

    return NULL;
    }
  d = &((*d)->next);
  }

if (action != dest_add) return NULL;

dd = (dest_item *)store_malloc(sizeof(dest_item) + Ustrlen(name));
Ustrcpy(dd->address, name);
dd->next = NULL;
dd->parent = NULL;
*d = dd;
return dd;
}



/*************************************************
*            Clean up a dead queue item          *
*************************************************/

static void
clean_up(queue_item *p)
{
dest_item *dd = p->destinations;
while (dd != NULL)
  {
  dest_item *next = dd->next;
  store_free(dd);
  dd = next;
  }
if (p->sender != NULL) store_free(p->sender);
store_free(p);
}


/*************************************************
*         Set up an ACL variable                 *
*************************************************/

/* The spool_read_header() function calls acl_var_create() when it reads in an
ACL variable. We know that in this case, the variable will be new, not re-used,
so this is a cut-down version, to save including the whole acl.c module (which
would need conditional compilation to cut most of it out). */

tree_node *
acl_var_create(uschar *name)
{
tree_node *node, **root;
root = (name[0] == 'c')? &acl_var_c : &acl_var_m;
node = store_get(sizeof(tree_node) + Ustrlen(name));
Ustrcpy(node->name, name);
node->data.ptr = NULL;
(void)tree_insertnode(root, node);
return node;
}



/*************************************************
*             Set up new queue item              *
*************************************************/

static queue_item *
set_up(uschar *name, int dir_char)
{
int i, rc, save_errno;
struct stat statdata;
void *reset_point;
uschar *p;
queue_item *q = (queue_item *)store_malloc(sizeof(queue_item));
uschar buffer[256];

/* Initialize the block */

q->next = q->prev = NULL;
q->destinations = NULL;
Ustrncpy(q->name, name, sizeof(q->name));
q->seen = TRUE;
q->frozen = FALSE;
q->dir_char = dir_char;
q->sender = NULL;
q->size = 0;

/* Read the header file from the spool; if there is a failure it might mean
inaccessibility as a result of protections. A successful read will have caused
sender_address to get set and the recipients fields to be initialized. If
there's a format error in the headers, we can still display info from the
envelope.

Before reading the header remember the position in the dynamic store so that
we can recover the store into which the header is read. All data read by
spool_read_header that is to be preserved is copied into malloc store. */

reset_point = store_get(0);
message_size = 0;
message_subdir[0] = dir_char;
sprintf(CS buffer, "%s-H", name);
rc =  spool_read_header(buffer, FALSE, TRUE);
save_errno = errno;

/* If we failed to read the envelope, compute the input time by
interpreting the id as a base-62 number. */

if (rc != spool_read_OK && rc != spool_read_hdrerror)
  {
  int t = 0;
  for (i = 0; i < 6; i++) t = t * 62 + tab62[name[i] - '0'];
  q->update_time = q->input_time = t;
  }

/* Envelope read; get input time and remove qualify_domain from sender address,
if it's there. */

else
  {
  q->update_time = q->input_time = received_time.tv_sec;
  if ((p = strstric(sender_address+1, qualify_domain, FALSE)) != NULL &&
    *(--p) == '@') *p = 0;
  }

/* If we didn't read the whole header successfully, generate an error
message. If the envelope was read, this appears as a first recipient;
otherwise it sets set up in the sender field. */

if (rc != spool_read_OK)
  {
  uschar *msg;

  if (save_errno == ERRNO_SPOOLFORMAT)
    {
    struct stat statbuf;
    sprintf(CS big_buffer, "%s/input/%s", spool_directory, buffer);
    if (Ustat(big_buffer, &statbuf) == 0)
      msg = string_sprintf("*** Format error in spool file: size = %d ***",
        statbuf.st_size);
    else msg = string_sprintf("*** Format error in spool file ***");
    }
  else msg = string_sprintf("*** Cannot read spool file ***");

  if (rc == spool_read_hdrerror)
    {
    (void)find_dest(q, msg, dest_add, FALSE);
    }
  else
    {
    f.deliver_freeze = FALSE;
    sender_address = msg;
    recipients_count = 0;
    }
  }

/* Now set up the remaining data. */

q->frozen = f.deliver_freeze;

if (f.sender_set_untrusted)
  {
  if (sender_address[0] == 0)
    {
    q->sender = store_malloc(Ustrlen(originator_login) + 6);
    sprintf(CS q->sender, "<> (%s)", originator_login);
    }
  else
    {
    q->sender = store_malloc(Ustrlen(sender_address) +
      Ustrlen(originator_login) + 4);
    sprintf(CS q->sender, "%s (%s)", sender_address, originator_login);
    }
  }
else
  {
  q->sender = store_malloc(Ustrlen(sender_address) + 1);
  Ustrcpy(q->sender, sender_address);
  }

sender_address = NULL;

snprintf(CS buffer, sizeof(buffer), "%s/input/%s/%s/%s-D",
  spool_directory, queue_name, message_subdir, name);
if (Ustat(buffer, &statdata) == 0)
  q->size = message_size + statdata.st_size - SPOOL_DATA_START_OFFSET + 1;

/* Scan and process the recipients list, skipping any that have already
been delivered, and removing visible names. */

if (recipients_list != NULL)
  for (i = 0; i < recipients_count; i++)
    {
    uschar *r = recipients_list[i].address;
    if (tree_search(tree_nonrecipients, r) == NULL)
      {
      if ((p = strstric(r+1, qualify_domain, FALSE)) != NULL &&
        *(--p) == '@') *p = 0;
      (void)find_dest(q, r, dest_add, FALSE);
      }
    }

/* Recover the dynamic store used by spool_read_header(). */

store_reset(reset_point);
return q;
}



/*************************************************
*             Find/Create a queue item           *
*************************************************/

/* The queue is kept as a doubly-linked list, sorted by name. However,
to speed up searches, an index into the list is used. This is maintained
by the scan_spool_input function when it goes down the list throwing
out entries that are no longer needed. When the action is "add" and
we don't need to add, mark the found item as seen. */


#ifdef never
static void debug_queue(void)
{
int i;
int count = 0;
queue_item *p;
printf("\nqueue_total=%d\n", queue_total);

for (i = 0; i < queue_index_size; i++)
  printf("index %d = %d %s\n", i, (int)(queue_index[i]),
    (queue_index[i])->name);

printf("Queue is:\n");
p = queue_index[0];
while (p != NULL)
  {
  count++;
  for (i = 0; i < queue_index_size; i++)
    {
    if (queue_index[i] == p) printf("count=%d index=%d\n", count, (int)p);
    }
  printf("%d %d %d %s\n", (int)p, (int)p->next, (int)p->prev, p->name);
  p = p->next;
  }
}
#endif



queue_item *
find_queue(uschar *name, int action, int dir_char)
{
int first = 0;
int last = queue_index_size - 1;
int middle = (first + last)/2;
queue_item *p, *q, *qq;

/* Handle the empty queue as a special case. */

if (queue_total == 0)
  {
  if (action != queue_add) return NULL;
  if ((qq = set_up(name, dir_char)) != NULL)
    {
    int i;
    for (i = 0; i < queue_index_size; i++) queue_index[i] = qq;
    queue_total++;
    return qq;
    }
  return NULL;
  }

/* Also handle insertion at the start or end of the queue
as special cases. */

if (Ustrcmp(name, (queue_index[0])->name) < 0)
  {
  if (action != queue_add) return NULL;
  if ((qq = set_up(name, dir_char)) != NULL)
    {
    qq->next = queue_index[0];
    (queue_index[0])->prev = qq;
    queue_index[0] = qq;
    queue_total++;
    return qq;
    }
  return NULL;
  }

if (Ustrcmp(name, (queue_index[queue_index_size-1])->name) > 0)
  {
  if (action != queue_add) return NULL;
  if ((qq = set_up(name, dir_char)) != NULL)
    {
    qq->prev = queue_index[queue_index_size-1];
    (queue_index[queue_index_size-1])->next = qq;
    queue_index[queue_index_size-1] = qq;
    queue_total++;
    return qq;
    }
  return NULL;
  }

/* Use binary chopping on the index to get a range of the queue to search
when the name is somewhere in the middle, if present. */

while (middle > first)
  {
  if (Ustrcmp(name, (queue_index[middle])->name) >= 0) first = middle;
    else last = middle;
  middle = (first + last)/2;
  }

/* Now search down the part of the queue in which the item must
lie if it exists. Both end points are inclusive - though in fact
the bottom one can only be = if it is the original bottom. */

p = queue_index[first];
q = queue_index[last];

for (;;)
  {
  int c = Ustrcmp(name, p->name);

  /* Already on queue; mark seen if required. */

  if (c == 0)
    {
    if (action == queue_add) p->seen = TRUE;
    return p;
    }

  /* Not on the queue; add an entry if required. Note that set-up might
  fail (the file might vanish under our feet). Note also that we know
  there is always a previous item to p because the end points are
  inclusive. */

  else if (c < 0)
    {
    if (action == queue_add)
      {
      if ((qq = set_up(name, dir_char)) != NULL)
        {
        qq->next = p;
        qq->prev = p->prev;
        p->prev->next = qq;
        p->prev = qq;
        queue_total++;
        return qq;
        }
      }
    return NULL;
    }

  /* Control should not reach here if p == q, because the name
  is supposed to be <= the name of the bottom item. */

  if (p == q) return NULL;

  /* Else might be further down the queue; continue */

  p = p->next;
  }

/* Control should never reach here. */
}



/*************************************************
*        Scan the exim spool directory           *
*************************************************/

/* If we discover that there are subdirectories, set a flag so that the menu
code knows to look for them. We count the entries to set the value for the
queue stripchart, and set up data for the queue display window if the "full"
option is given. */

void scan_spool_input(int full)
{
int i;
int subptr;
int subdir_max = 1;
int count = 0;
int indexptr = 1;
queue_item *p;
struct dirent *ent;
DIR *dd;
uschar input_dir[256];
uschar subdirs[64];

subdirs[0] = 0;
stripchart_total[0] = 0;

sprintf(CS input_dir, "%s/input", spool_directory);
subptr = Ustrlen(input_dir);
input_dir[subptr+2] = 0;               /* terminator for lengthened name */

/* Loop for each spool file on the queue - searching any subdirectories that
may exist. When initializing eximon, every file will have to be read. To show
there is progress, output a dot for each one to the standard output. */

for (i = 0; i < subdir_max; i++)
  {
  int subdirchar = subdirs[i];      /* 0 for main directory */
  if (subdirchar != 0)
    {
    input_dir[subptr] = '/';
    input_dir[subptr+1] = subdirchar;
    }

  dd = opendir(CS input_dir);
  if (dd == NULL) continue;

  while ((ent = readdir(dd)) != NULL)
    {
    uschar *name = US ent->d_name;
    int len = Ustrlen(name);

    /* If we find a single alphameric sub-directory on the first
    pass, add it to the list for subsequent scans, and remember that
    we are dealing with a split directory. */

    if (i == 0 && len == 1 && isalnum(*name))
      {
      subdirs[subdir_max++] = *name;
      spool_is_split = TRUE;
      continue;
      }

    /* Otherwise, if it is a header spool file, add it to the list */

    if (len == SPOOL_NAME_LENGTH &&
        name[SPOOL_NAME_LENGTH - 2] == '-' &&
        name[SPOOL_NAME_LENGTH - 1] == 'H')
      {
      uschar basename[SPOOL_NAME_LENGTH + 1];
      stripchart_total[0]++;
      if (!eximon_initialized) { printf("."); fflush(stdout); }
      Ustrcpy(basename, name);
      basename[SPOOL_NAME_LENGTH - 2] = 0;
      if (full) find_queue(basename, queue_add, subdirchar);
      }
    }
  closedir(dd);
  }

/* If simply counting the number, we are done; same if there are no
items in the in-store queue. */

if (!full || queue_total == 0) return;

/* Now scan the queue and remove any items that were not in the directory. At
the same time, set up the index pointers into the queue. Because we are
removing items, the total that we are comparing against isn't actually correct,
but in a long queue it won't make much difference, and in a short queue it
doesn't matter anyway!*/

p = queue_index[0];
while (p != NULL)
  {
  if (!p->seen)
    {
    queue_item *next = p->next;
    if (p->prev == NULL) queue_index[0] = next;
      else p->prev->next = next;
    if (next == NULL)
      {
      int i;
      queue_item *q = queue_index[queue_index_size-1];
      for (i = queue_index_size - 1; i >= 0; i--)
        if (queue_index[i] == q) queue_index[i] = p->prev;
      }
    else next->prev = p->prev;
    clean_up(p);
    queue_total--;
    p = next;
    }
  else
    {
    if (++count > (queue_total * indexptr)/(queue_index_size-1))
      {
      queue_index[indexptr++] = p;
      }
    p->seen = FALSE;  /* for next time */
    p = p->next;
    }
  }

/* If a lot of messages have been removed at the bottom, we may not
have got the index all filled in yet. Make sure all the pointers
are legal. */

while (indexptr < queue_index_size - 1)
  {
  queue_index[indexptr++] = queue_index[queue_index_size-1];
  }
}




/*************************************************
*    Update the recipients list for a message    *
*************************************************/

/* We read the spool file only if its update time differs from last time,
or if there is a journal file in existence. */

/* First, a local subroutine to scan the non-recipients tree and
remove any of them from the address list */

static void
scan_tree(queue_item *p, tree_node *tn)
{
if (tn != NULL)
  {
  if (tn->left != NULL) scan_tree(p, tn->left);
  if (tn->right != NULL) scan_tree(p, tn->right);
  (void)find_dest(p, tn->name, dest_remove, FALSE);
  }
}

/* The main function */

static void update_recipients(queue_item *p)
{
int i;
FILE *jread;
void *reset_point;
struct stat statdata;
uschar buffer[1024];

message_subdir[0] = p->dir_char;

snprintf(CS buffer, sizeof(buffer), "%s/input/%s/%s/%s-J",
  spool_directory, queue_name, message_subdir, p->name);

if (!(jread = fopen(CS buffer, "r")))
  {
  snprintf(CS buffer, sizeof(buffer), "%s/input/%s/%s/%s-H",
    spool_directory, queue_name, message_subdir, p->name);
  if (Ustat(buffer, &statdata) < 0 || p->update_time == statdata.st_mtime)
    return;
  }

/* Get the contents of the header file; if any problem, just give up.
Arrange to recover the dynamic store afterwards. */

reset_point = store_get(0);
sprintf(CS buffer, "%s-H", p->name);
if (spool_read_header(buffer, FALSE, TRUE) != spool_read_OK)
  {
  store_reset(reset_point);
  if (jread != NULL) fclose(jread);
  return;
  }

/* If there's a journal file, add its contents to the non-recipients tree */

if (jread != NULL)
  {
  while (Ufgets(big_buffer, big_buffer_size, jread) != NULL)
    {
    int n = Ustrlen(big_buffer);
    big_buffer[n-1] = 0;
    tree_add_nonrecipient(big_buffer);
    }
  fclose(jread);
  }

/* Scan and process the recipients list, removing any that have already
been delivered, and removing visible names. In the nonrecipients tree,
domains are lower cased. */

if (recipients_list)
  for (i = 0; i < recipients_count; i++)
    {
    uschar * pp;
    uschar * r = recipients_list[i].address;
    tree_node * node;

    if (!(node = tree_search(tree_nonrecipients, r)))
      node = tree_search(tree_nonrecipients, string_copylc(r));

    if ((pp = strstric(r+1, qualify_domain, FALSE)) && *(--pp) == '@')
       *pp = 0;
    if (!node)
      (void)find_dest(p, r, dest_add, FALSE);
    else
      (void)find_dest(p, r, dest_remove, FALSE);
    }

/* We also need to scan the tree of non-recipients, which might
contain child addresses that are not in the recipients list, but
which may have got onto the address list as a result of eximon
noticing an == line in the log. Then remember the update time,
recover the dynamic store, and we are done. */

scan_tree(p, tree_nonrecipients);
p->update_time = statdata.st_mtime;
store_reset(reset_point);
}



/*************************************************
*              Display queue data                *
*************************************************/

/* The present implementation simple re-writes the entire information each
time. Take some care to keep the scrolled position as it previously was, but,
if it was at the bottom, keep it at the bottom. Take note of any hide list, and
time out the entries as appropriate. */

void
queue_display(void)
{
int now = (int)time(NULL);
queue_item *p = queue_index[0];

if (menu_is_up) return;            /* Avoid nasty interactions */

text_empty(queue_widget);

while (p != NULL)
  {
  int count = 1;
  dest_item *dd, *ddd;
  uschar u = 'm';
  int t = (now - p->input_time)/60;  /* minutes on queue */

  if (t > 90)
    {
    u = 'h';
    t = (t + 30)/60;
    if (t > 72)
      {
      u = 'd';
      t = (t + 12)/24;
      if (t > 99)                    /* someone had > 99 days */
        {
        u = 'w';
        t = (t + 3)/7;
        if (t > 99)                  /* so, just in case */
          {
          u = 'y';
          t = (t + 26)/52;
          }
        }
      }
    }

  update_recipients(p);                   /* update destinations */

  /* Can't set this earlier, as header data may change things. */

  dd = p->destinations;

  /* Check to see if this message is on the hide list; if any hide
  item has timed out, remove it from the list. Hide if all destinations
  are on the hide list. */

  for (ddd = dd; ddd != NULL; ddd = ddd->next)
    {
    skip_item *sk;
    skip_item **skp;
    int len_address;

    if (ddd->address[0] == '*') break;
    len_address = Ustrlen(ddd->address);

    for (skp = &queue_skip; ; skp = &(sk->next))
      {
      int len_skip;

      sk = *skp;
      while (sk != NULL && now >= sk->reveal)
        {
        *skp = sk->next;
        store_free(sk);
        sk = *skp;
        if (queue_skip == NULL)
          {
          XtDestroyWidget(unhide_widget);
          unhide_widget = NULL;
          }
        }
      if (sk == NULL) break;

      /* If this address matches the skip item, break (sk != NULL) */

      len_skip = Ustrlen(sk->text);
      if (len_skip <= len_address &&
          Ustrcmp(ddd->address + len_address - len_skip, sk->text) == 0)
        break;
      }

    if (sk == NULL) break;
    }

  /* Don't use more than one call of anon() in one statement - it uses
  a fixed static buffer. */

  if (ddd != NULL || dd == NULL)
    {
    text_showf(queue_widget, "%c%2d%c %s %s %-8s ",
      (p->frozen)? '*' : ' ',
      t, u,
      string_format_size(p->size, big_buffer),
      p->name,
      (p->sender == NULL)? US"       " :
        (p->sender[0] == 0)? US"<>     " : anon(p->sender));

    text_showf(queue_widget, "%s%s%s",
      (dd == NULL || dd->address[0] == '*')? "" : "<",
      (dd == NULL)? US"" : anon(dd->address),
      (dd == NULL || dd->address[0] == '*')? "" : ">");

    if (dd != NULL && dd->parent != NULL && dd->parent->address[0] != '*')
      text_showf(queue_widget, " parent <%s>", anon(dd->parent->address));

    text_show(queue_widget, US"\n");

    if (dd != NULL) dd = dd->next;
    while (dd != NULL && count++ < queue_max_addresses)
      {
      text_showf(queue_widget, "                                     <%s>",
        anon(dd->address));
      if (dd->parent != NULL && dd->parent->address[0] != '*')
        text_showf(queue_widget, " parent <%s>", anon(dd->parent->address));
      text_show(queue_widget, US"\n");
      dd = dd->next;
      }
    if (dd != NULL)
      text_showf(queue_widget, "                                     ...\n");
    }

  p = p->next;
  }
}

/* End of em_queue.c */
