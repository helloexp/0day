/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* SHA routine selection */

#include "exim.h"

/* Please be aware that pulling in extra headers which are not in the system
 * includes may require careful juggling of CFLAGS in
 * scripts/Configure-Makefile -- that logic should be kept in sync with this.
 * In particular, building with just something like USE_OPENSSL_PC=openssl
 * and not massaging CFLAGS in Local/Makefile is fully supported.
 */

#ifdef SUPPORT_TLS

# define EXIM_HAVE_SHA2

# ifdef USE_GNUTLS
#  include <gnutls/gnutls.h>

#  if GNUTLS_VERSION_NUMBER >= 0x020a00
#   define SHA_GNUTLS
#   if GNUTLS_VERSION_NUMBER >= 0x030500
#    define EXIM_HAVE_SHA3		/*MMMM*/
#   endif
#  else
#   define SHA_GCRYPT
#  endif

# else
#  define SHA_OPENSSL
#  include <openssl/ssl.h>
#  if (OPENSSL_VERSION_NUMBER >= 0x10101000L) && !defined(LIBRESSL_VERSION_NUMBER)
#   define EXIM_HAVE_SHA3
#  endif
# endif

#else
# define SHA_NATIVE
#endif

