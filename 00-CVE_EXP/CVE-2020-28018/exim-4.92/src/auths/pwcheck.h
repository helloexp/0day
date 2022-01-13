/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */

/* This file provides support for authentication via the Cyrus SASL pwcheck
daemon (whence its name) and the newer saslauthd daemon. */

/* Error codes used internally within the authentication functions */

/* PWCHECK_OK   - auth successful
   PWCHECK_NO   - access denied
   PWCHECK_FAIL - [temporary] failure */

#define PWCHECK_OK   0
#define PWCHECK_NO   1
#define PWCHECK_FAIL 2

/* Cyrus functions for doing the business. */

extern int pwcheck_verify_password(const char *, const char *, const char **);
extern int saslauthd_verify_password(const uschar *, const uschar *,
           const uschar *, const uschar *, const uschar **);

/* End of pwcheck.h */
