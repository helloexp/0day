/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions for maintaining binary balanced trees and some associated
functions as well. */


#include "exim.h"




/*************************************************
*        Add entry to non-recipients tree        *
*************************************************/

/* Duplicates are just discarded.

Arguments:
  s       string to add

Returns:  nothing
*/

void
tree_add_nonrecipient(uschar *s)
{
tree_node *node = store_get(sizeof(tree_node) + Ustrlen(s));
Ustrcpy(node->name, s);
node->data.ptr = NULL;
if (!tree_insertnode(&tree_nonrecipients, node)) store_reset(node);
}



/*************************************************
*        Add entry to duplicates tree            *
*************************************************/

/* Duplicates are just discarded.

Argument:
  s       string to add
  addr    the address is is a duplicate of

Returns:  nothing
*/

void
tree_add_duplicate(uschar *s, address_item *addr)
{
tree_node *node = store_get(sizeof(tree_node) + Ustrlen(s));
Ustrcpy(node->name, s);
node->data.ptr = addr;
if (!tree_insertnode(&tree_duplicates, node)) store_reset(node);
}



/*************************************************
*    Add entry to unusable addresses tree        *
*************************************************/

/* Duplicates are simply discarded.

Argument:    the host item
Returns:     nothing
*/

void
tree_add_unusable(host_item *h)
{
tree_node *node;
uschar s[256];
sprintf(CS s, "T:%.200s:%s", h->name, h->address);
node = store_get(sizeof(tree_node) + Ustrlen(s));
Ustrcpy(node->name, s);
node->data.val = h->why;
if (h->status == hstatus_unusable_expired) node->data.val += 256;
if (!tree_insertnode(&tree_unusable, node)) store_reset(node);
}



/*************************************************
*        Write a tree in re-readable form        *
*************************************************/

/* This function writes out a tree in a form in which it can
easily be re-read. It is used for writing out the non-recipients
tree onto the spool, for retrieval at the next retry time.

The format is as follows:

   . If the tree is empty, write one line containing XX.

   . Otherwise, each node is written, preceded by two letters
     (Y/N) indicating whether it has left or right children.

   . The left subtree (if any) then follows, then the right subtree.

First, there's an internal recursive subroutine.

Arguments:
  p          current node
  f          FILE to write to

Returns:     nothing
*/

static void
write_tree(tree_node *p, FILE *f)
{
fprintf(f, "%c%c %s\n",
  (p->left == NULL)? 'N':'Y', (p->right == NULL)? 'N':'Y', p->name);
if (p->left != NULL) write_tree(p->left, f);
if (p->right != NULL) write_tree(p->right, f);
}

/* This is the top-level function, with the same arguments. */

void
tree_write(tree_node *p, FILE *f)
{
if (p == NULL)
  {
  fprintf(f, "XX\n");
  return;
  }
write_tree(p, f);
}





/***********************************************************
*          Binary Balanced Tree Management Routines        *
***********************************************************/

/* This set of routines maintains a balanced binary tree using
the algorithm given in Knuth Vol 3 page 455.

The routines make use of uschar * pointers as byte pointers,
so as to be able to do arithmetic on them, since ANSI Standard
C does not permit additions and subtractions on void pointers. */


/*************************************************
*              Flags and Parameters              *
*************************************************/

#define tree_lbal      1         /* left subtree is longer */
#define tree_rbal      2         /* right subtree is longer */
#define tree_bmask     3         /* mask for flipping bits */


/*************************************************
*         Insert a new node into a tree          *
*************************************************/

/* The node->name field must (obviously) be set, but the other
fields need not be initialized.

Arguments:
  treebase   pointer to the root of the tree
  node       the note to insert, with name field set

Returns:     TRUE if node inserted; FALSE if not (duplicate)
*/

int
tree_insertnode(tree_node **treebase, tree_node *node)
{
tree_node *p = *treebase;
tree_node **q, *r, *s, **t;
int a;

node->left = node->right = NULL;
node->balance = 0;

/* Deal with an empty tree */

if (p == NULL)
  {
  *treebase = node;
  return TRUE;
  }

/* The tree is not empty. While finding the insertion point,
q points to the pointer to p, and t points to the pointer to
the potential re-balancing point. */

q = treebase;
t = q;

/* Loop to search tree for place to insert new node */

for (;;)
  {
  int c = Ustrcmp(node->name, p->name);
  if (c == 0) return FALSE;              /* Duplicate node encountered */

  /* Deal with climbing down the tree, exiting from the loop
  when we reach a leaf. */

  q = (c > 0)? &(p->right) : &(p->left);
  p = *q;
  if (p == NULL) break;

  /* Save the address of the pointer to the last node en route
  which has a non-zero balance factor. */

  if (p->balance != 0) t = q;
  }

/* When the above loop completes, q points to the pointer to NULL;
that is the place at which the new node must be inserted. */

*q = node;

/* Set up s as the potential re-balancing point, and r as the
next node after it along the route. */

s = *t;
r = (Ustrcmp(node->name, s->name) > 0)? s->right : s->left;

/* Adjust balance factors along the route from s to node. */

p = r;

while (p != node)
  {
  if (Ustrcmp(node->name, p->name) < 0)
    {
    p->balance = tree_lbal;
    p = p->left;
    }
  else
    {
    p->balance = tree_rbal;
    p = p->right;
    }
  }

/* Now the World-Famous Balancing Act */

a = (Ustrcmp(node->name, s->name) < 0)? tree_lbal : tree_rbal;

if (s->balance == 0) s->balance = (uschar)a;        /* The tree has grown higher */
  else if (s->balance != (uschar)a) s->balance = 0; /* It's become more balanced */
else                                              /* It's got out of balance */
  {
  /* Perform a single rotation */

  if (r->balance == (uschar)a)
    {
    p = r;
    if (a == tree_rbal)
      {
      s->right = r->left;
      r->left = s;
      }
    else
      {
      s->left = r->right;
      r->right = s;
      }
    s->balance = 0;
    r->balance = 0;
    }

  /* Perform a double rotation There was an occasion when the balancing
  factors were screwed up by a bug in the code that reads a tree from
  the spool. In case this ever happens again, check for changing p to NULL
  and don't do it. It is better to have an unbalanced tree than a crash. */

  else
    {
    if (a == tree_rbal)
      {
      if (r->left == NULL) return TRUE;   /* Bail out if tree corrupt */
      p = r->left;
      r->left = p->right;
      p->right = r;
      s->right = p->left;
      p->left = s;
      }
    else
      {
      if (r->right == NULL) return TRUE;  /* Bail out if tree corrupt */
      p = r->right;
      r->right = p->left;
      p->left = r;
      s->left = p->right;
      p->right = s;
      }

    s->balance = (p->balance == (uschar)a)? (uschar)(a^tree_bmask) : 0;
    r->balance = (p->balance == (uschar)(a^tree_bmask))? (uschar)a : 0;
    p->balance = 0;
    }

  /* Finishing touch */

  *t = p;
  }

return TRUE;     /* Successful insertion */
}



/*************************************************
*          Search tree for node by name          *
*************************************************/

/*
Arguments:
  p         root of tree
  name      key to search for

Returns:    pointer to node, or NULL if not found
*/

tree_node *
tree_search(tree_node *p, const uschar *name)
{
while (p)
  {
  int c = Ustrcmp(name, p->name);
  if (c == 0) return p;
  p = c < 0 ? p->left : p->right;
  }
return NULL;
}



/*************************************************
*   Walk tree recursively and execute function   *
*************************************************/

/*
Arguments:
  p       root of the tree
  f       function to execute for each name-value-pair
  ctx     context data for f
*/

void
tree_walk(tree_node *p, void (*f)(uschar*, uschar*, void*), void *ctx)
{
if (!p) return;
f(p->name, p->data.ptr, ctx);
tree_walk(p->left, f, ctx);
tree_walk(p->right, f, ctx);
}


/* End of tree.c */
