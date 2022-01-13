# Make file for building a library containing all the available transports and
# calling it transports.a. This is called from the main make file, after cd'ing
# to the transports subdirectory.

OBJ = appendfile.o autoreply.o lmtp.o pipe.o queuefile.o smtp.o smtp_socks.o tf_maildir.o

transports.a:    $(OBJ)
		 @$(RM_COMMAND) -f transports.a
		 @echo "$(AR) transports.a"
		 @$(AR) transports.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

appendfile.o:    $(HDRS) appendfile.c appendfile.h tf_maildir.h
autoreply.o:     $(HDRS) autoreply.c autoreply.h
lmtp.o:          $(HDRS) lmtp.c lmtp.h
pipe.o:          $(HDRS) pipe.c pipe.h
queuefile.o:     $(HDRS) queuefile.c queuefile.h
smtp.o:          $(HDRS) smtp.c smtp.h
smtp_socks.o:    $(HDRS) smtp_socks.c smtp.h

tf_maildir.o:    $(HDRS) tf_maildir.c tf_maildir.h appendfile.h

# End
