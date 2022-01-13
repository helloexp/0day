# Make file for building Exim's lookup modules.
# This is called from the main make file, after cd'ing
# to the lookups subdirectory.

# nb: at build time, the version of this file used will have had some
#     extra variable definitions and prepended to it and module build rules
#     interpolated below.

# MAGIC-TAG-MODS-OBJ-RULES-GO-HERE


all:             lookups.a lf_quote.o lf_check_file.o lf_sqlperform.o $(MODS)

lookups.a:       $(OBJ)
		 @$(RM_COMMAND) -f lookups.a
		 @echo "$(AR) lookups.a"
		 @$(AR) lookups.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c .so
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

.c.so:;          @echo "$(CC) -shared $*.c"
		 $(FE)$(CC) $(LOOKUP_$*_INCLUDE) $(LOOKUP_$*_LIBS) -DDYNLOOKUP $(CFLAGS_DYNAMIC) $(CFLAGS) $(INCLUDE) $(DLFLAGS) $*.c -o $@

lf_check_file.o: $(PHDRS) lf_check_file.c  lf_functions.h
lf_quote.o:      $(PHDRS) lf_quote.c       lf_functions.h
lf_sqlperform.o: $(PHDRS) lf_sqlperform.c  lf_functions.h

cdb.o:           $(PHDRS) cdb.c
dbmdb.o:         $(PHDRS) dbmdb.c
dnsdb.o:         $(PHDRS) dnsdb.c
dsearch.o:       $(PHDRS) dsearch.c
ibase.o:         $(PHDRS) ibase.c
ldap.o:          $(PHDRS) ldap.c
lmdb.o:          $(PHDRS) lmdb.c
lsearch.o:       $(PHDRS) lsearch.c
mysql.o:         $(PHDRS) mysql.c
nis.o:           $(PHDRS) nis.c
nisplus.o:       $(PHDRS) nisplus.c
oracle.o:        $(PHDRS) oracle.c
passwd.o:        $(PHDRS) passwd.c
pgsql.o:         $(PHDRS) pgsql.c
redis.o:         $(PHDRS) redis.c
spf.o:           $(PHDRS) spf.c
sqlite.o:        $(PHDRS) sqlite.c
testdb.o:        $(PHDRS) testdb.c
whoson.o:        $(PHDRS) whoson.c

cdb.so:           $(PHDRS) cdb.c
dbmdb.so:         $(PHDRS) dbmdb.c
dnsdb.so:         $(PHDRS) dnsdb.c
dsearch.so:       $(PHDRS) dsearch.c
ibase.so:         $(PHDRS) ibase.c
ldap.so:          $(PHDRS) ldap.c
lmdb.so:          $(PHDRS) lmdb.c
lsearch.so:       $(PHDRS) lsearch.c
mysql.so:         $(PHDRS) mysql.c
nis.so:           $(PHDRS) nis.c
nisplus.so:       $(PHDRS) nisplus.c
oracle.so:        $(PHDRS) oracle.c
passwd.so:        $(PHDRS) passwd.c
pgsql.so:         $(PHDRS) pgsql.c
redis.so:         $(PHDRS) redis.c
spf.so:           $(PHDRS) spf.c
sqlite.so:        $(PHDRS) sqlite.c
testdb.so:        $(PHDRS) testdb.c
whoson.so:        $(PHDRS) whoson.c

# End
