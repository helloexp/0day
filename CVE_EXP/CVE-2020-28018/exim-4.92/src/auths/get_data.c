/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

#include "../exim.h"


/*************************************************
*      Issue a challenge and get a response      *
*************************************************/

/* This function is used by authentication drivers to output a challenge
to the SMTP client and read the response line.

Arguments:
   aptr       set to point to the response (which is in big_buffer)
   challenge  the challenge text (unencoded, may be binary)
   challen    the length of the challenge text

Returns:      OK on success
              BAD64 if response too large for buffer
              CANCELLED if response is "*"
*/

int
auth_get_data(uschar **aptr, uschar *challenge, int challen)
{
int c;
int p = 0;
smtp_printf("334 %s\r\n", FALSE, b64encode(challenge, challen));
while ((c = receive_getc(GETC_BUFFER_UNLIMITED)) != '\n' && c != EOF)
  {
  if (p >= big_buffer_size - 1) return BAD64;
  big_buffer[p++] = c;
  }
if (p > 0 && big_buffer[p-1] == '\r') p--;
big_buffer[p] = 0;
DEBUG(D_receive) debug_printf("SMTP<< %s\n", big_buffer);
if (Ustrcmp(big_buffer, "*") == 0) return CANCELLED;
*aptr = big_buffer;
return OK;
}

/* End of get_data.c */
