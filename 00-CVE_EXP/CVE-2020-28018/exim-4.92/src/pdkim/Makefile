# Make file for building the pdkim library.
# Copyright (c) The Exim Maintainers 1995 - 2018

OBJ = pdkim.o signing.o

pdkim.a:         $(OBJ)
		 @$(RM_COMMAND) -f pdkim.a
		 @echo "$(AR) pdkim.a"
		 $(FE)$(AR) pdkim.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) -I. $*.c

pdkim.o: $(HDRS) crypt_ver.h pdkim.h pdkim.c
signing.o: $(HDRS) crypt_ver.h signing.h signing.c

# End
