# Make file for building a library containing all the available authorization
# methods, and calling it auths.a. In addition, there are functions that are
# of general use in several methods; these are in separate modules so they are
# linked in only when needed. This Makefile is called from the main make file,
# after cd'ing to the auths subdirectory. When the relevant AUTH_ macros are
# defined, the equivalent modules herein is not included in the final binary.

OBJ = auth-spa.o call_pam.o call_pwcheck.o \
      call_radius.o check_serv_cond.o cram_md5.o cyrus_sasl.o dovecot.o \
      get_data.o get_no64_data.o gsasl_exim.o heimdal_gssapi.o \
      md5.o plaintext.o pwcheck.o \
      spa.o tls.o xtextdecode.o xtextencode.o

auths.a:         $(OBJ)
		 @$(RM_COMMAND) -f auths.a
		 @echo "$(AR) auths.a"
		 $(FE)$(AR) auths.a $(OBJ)
		 $(RANLIB) $@

.SUFFIXES:       .o .c
.c.o:;           @echo "$(CC) $*.c"
		 $(FE)$(CC) -c $(CFLAGS) $(INCLUDE) $*.c

auth-spa.o:         $(HDRS) auth-spa.c
call_pam.o:         $(HDRS) call_pam.c
call_pwcheck.o:     $(HDRS) call_pwcheck.c pwcheck.h
call_radius.o:      $(HDRS) call_radius.c
check_serv_cond.o:  $(HDRS) check_serv_cond.c
get_data.o:         $(HDRS) get_data.c
get_no64_data.o:    $(HDRS) get_no64_data.c
md5.o:              $(HDRS) md5.c
pwcheck.o:          $(HDRS) pwcheck.c pwcheck.h
xtextdecode.o:      $(HDRS) xtextdecode.c
xtextencode.o:      $(HDRS) xtextencode.c

cram_md5.o:         $(HDRS) cram_md5.c cram_md5.h
cyrus_sasl.o:       $(HDRS) cyrus_sasl.c cyrus_sasl.h
dovecot.o:          $(HDRS) dovecot.c dovecot.h
gsasl_exim.o:       $(HDRS) gsasl_exim.c gsasl_exim.h
heimdal_gssapi.o:   $(HDRS) heimdal_gssapi.c heimdal_gssapi.h
plaintext.o:        $(HDRS) plaintext.c plaintext.h
spa.o:              $(HDRS) spa.c spa.h
tls.o:              $(HDRS) tls.c tls.h

# End
