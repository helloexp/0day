# Make file for building a library containing all the available routers and
# calling it routers.a. This is called from the main make file, after cd'ing
# to the directors subdirectory. The library also contains functions that
# are called only from within the individual routers.

OBJ = accept.o dnslookup.o ipliteral.o iplookup.o manualroute.o \
      queryprogram.o redirect.o \
      rf_change_domain.o rf_expand_data.o rf_get_errors_address.o \
      rf_get_munge_headers.o rf_get_transport.o rf_get_ugid.o \
      rf_lookup_hostlist.o \
      rf_queue_add.o rf_self_action.o \
      rf_set_ugid.o

routers.a:       $(OBJ)
		 @$(RM_COMMAND) -f routers.a
		 @echo "$(AR) routers.a"
		 @$(AR) routers.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

rf_change_domain.o:      $(HDRS) rf_change_domain.c      rf_functions.h
rf_expand_data.o:        $(HDRS) rf_expand_data.c        rf_functions.h
rf_get_errors_address.o: $(HDRS) rf_get_errors_address.c rf_functions.h
rf_get_munge_headers.o:  $(HDRS) rf_get_munge_headers.c  rf_functions.h
rf_get_transport.o:      $(HDRS) rf_get_transport.c      rf_functions.h
rf_get_ugid.o:           $(HDRS) rf_get_ugid.c           rf_functions.h
rf_lookup_hostlist.o:    $(HDRS) rf_lookup_hostlist.c    rf_functions.h
rf_queue_add.o:          $(HDRS) rf_queue_add.c          rf_functions.h
rf_self_action.o:        $(HDRS) rf_self_action.c        rf_functions.h
rf_set_ugid.o:           $(HDRS) rf_set_ugid.c           rf_functions.h

accept.o:        $(HDRS) accept.c       rf_functions.h accept.h
dnslookup.o:     $(HDRS) dnslookup.c    rf_functions.h dnslookup.h
ipliteral.o:     $(HDRS) ipliteral.c    rf_functions.h ipliteral.h
iplookup.o:      $(HDRS) iplookup.c     rf_functions.h iplookup.h
manualroute.o:   $(HDRS) manualroute.c  rf_functions.h manualroute.h
queryprogram.o:  $(HDRS) queryprogram.c rf_functions.h queryprogram.h
redirect.o:      $(HDRS) redirect.c     rf_functions.h redirect.h

# End
