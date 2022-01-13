/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Signing and hashing routine selection for PDKIM */

#include "../exim.h"
#include "../sha_ver.h"


#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>

# if GNUTLS_VERSION_NUMBER >= 0x030000
#  define SIGN_GNUTLS
#  if GNUTLS_VERSION_NUMBER >= 0x030600
#   define SIGN_HAVE_ED25519
#  endif
# else
#  define SIGN_GCRYPT
# endif

#else
# define SIGN_OPENSSL
#  if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10101000L
#   define SIGN_HAVE_ED25519
#  endif

#endif

