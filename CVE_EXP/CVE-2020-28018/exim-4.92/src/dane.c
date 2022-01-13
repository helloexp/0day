/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2012, 2014 */
/* See the file NOTICE for conditions of use and distribution. */

/* This module provides DANE (RFC6659) support for Exim.  See also
the draft RFC for DANE-over-SMTP, "SMTP security via opportunistic DANE TLS"
(V. Dukhovni, W. Hardaker) - version 10, dated May 25, 2014.

The code for DANE support with Openssl was provided by V.Dukhovni.

No cryptographic code is included in Exim. All this module does is to call
functions from the OpenSSL or GNU TLS libraries. */


#include "exim.h"

/* This module is compiled only when it is specifically requested in the
build-time configuration. However, some compilers don't like compiling empty
modules, so keep them happy with a dummy when skipping the rest. Make it
reference itself to stop picky compilers complaining that it is unused, and put
in a dummy argument to stop even pickier compilers complaining about infinite
loops. */

#ifndef SUPPORT_DANE
static void dummy(int x) { dummy(x-1); }
#else

/* Enabling DANE without enabling TLS cannot work. Abort the compilation. */
# ifndef SUPPORT_TLS
#  error DANE support requires that TLS support must be enabled. Abort build.
# endif

/* DNSSEC support is also required */
# ifndef RES_USE_DNSSEC
#  error DANE support requires that the DNS resolver library supports DNSSEC
# endif

# ifndef USE_GNUTLS
#  include "dane-openssl.c"
# endif


#endif  /* SUPPORT_DANE */

/* End of dane.c */
