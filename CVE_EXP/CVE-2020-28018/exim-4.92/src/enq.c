/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2015 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions concerned with serialization. */


#include "exim.h"




/*************************************************
*       Test for host or ETRN serialization      *
*************************************************/

/* This function is called when a host is listed for serialization of
connections. It is also called when ETRN is listed for serialization. We open
the misc database and look for a record, which implies an existing connection
or ETRN run. If increasing the count would take us past the given limit
value return FALSE.  If not, bump it and return TRUE.  If not found, create
one with value 1 and return TRUE.

Arguments:
  key            string on which to serialize
  lim            parallelism limit

Returns:         TRUE if OK to proceed; FALSE otherwise
*/


BOOL
enq_start(uschar *key, unsigned lim)
{
dbdata_serialize *serial_record;
dbdata_serialize new_record;
open_db dbblock;
open_db *dbm_file;

DEBUG(D_transport) debug_printf("check serialized: %s\n", key);

/* Open and lock the waiting information database. The absence of O_CREAT is
deliberate; the dbfn_open() function - which is an Exim function - always tries
to create if it can't open a read/write file. It expects only O_RDWR or
O_RDONLY as its argument. */

if (!(dbm_file = dbfn_open(US"misc", O_RDWR, &dbblock, TRUE)))
  return FALSE;

/* See if there is a record for this host or queue run; if there is, we cannot
proceed with the connection unless the record is very old. */

serial_record = dbfn_read(dbm_file, key);
if (serial_record && time(NULL) - serial_record->time_stamp < 6*60*60)
  {
  if (serial_record->count >= lim)
    {
    dbfn_close(dbm_file);
    DEBUG(D_transport) debug_printf("outstanding serialization record for %s\n",
      key);
    return FALSE;
    }
  new_record.count = serial_record->count + 1;
  }
else
  new_record.count = 1;

/* We can proceed - insert a new record or update the old one. */

DEBUG(D_transport) debug_printf("write serialization record for %s val %d\n",
      key, new_record.count);
dbfn_write(dbm_file, key, &new_record, (int)sizeof(dbdata_serialize));
dbfn_close(dbm_file);
return TRUE;
}



/*************************************************
*              Release serialization             *
*************************************************/

/* This function is called when a serialized host's connection or serialized
ETRN queue run ends. We open the relevant database and delete its record.

Arguments:
  key          the serialization key

Returns:       nothing
*/

void
enq_end(uschar *key)
{
open_db dbblock;
open_db *dbm_file;
dbdata_serialize *serial_record;

DEBUG(D_transport) debug_printf("end serialized: %s\n", key);

if (  !(dbm_file = dbfn_open(US"misc", O_RDWR, &dbblock, TRUE))
   || !(serial_record = dbfn_read(dbm_file, key))
   )
  return;
if (--serial_record->count > 0)
  {
  DEBUG(D_transport) debug_printf("write serialization record for %s val %d\n",
      key, serial_record->count);
  dbfn_write(dbm_file, key, serial_record, (int)sizeof(dbdata_serialize));
  }
else
  {
  DEBUG(D_transport) debug_printf("remove serialization record for %s\n", key);
  dbfn_delete(dbm_file, key);
  }
dbfn_close(dbm_file);
}

/* End of enq.c */
