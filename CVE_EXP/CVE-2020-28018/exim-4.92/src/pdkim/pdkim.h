/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 2009 - 2012  Tom Kistner <tom@duncanthrax.net>
 *  Copyright (c) 2016 - 2018  Jeremy Harris
 *
 *  http://duncanthrax.net/pdkim/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef PDKIM_H
#define PDKIM_H

#include "../blob.h"
#include "../hash.h"

#define PDKIM_DEFAULT_SIGN_HEADERS "From:Sender:Reply-To:Subject:Date:"\
                             "Message-ID:To:Cc:MIME-Version:Content-Type:"\
                             "Content-Transfer-Encoding:Content-ID:"\
                             "Content-Description:Resent-Date:Resent-From:"\
                             "Resent-Sender:Resent-To:Resent-Cc:"\
                             "Resent-Message-ID:In-Reply-To:References:"\
                             "List-Id:List-Help:List-Unsubscribe:"\
                             "List-Subscribe:List-Post:List-Owner:List-Archive"

/* -------------------------------------------------------------------------- */
/* Length of the preallocated buffer for the "answer" from the dns/txt
   callback function. This should match the maximum RDLENGTH from DNS. */
#define PDKIM_DNS_TXT_MAX_RECLEN    (1 << 16)

/* -------------------------------------------------------------------------- */
/* Function success / error codes */
#define PDKIM_OK                      0
#define PDKIM_FAIL                   -1
#define PDKIM_ERR_RSA_PRIVKEY      -101
#define PDKIM_ERR_RSA_SIGNING      -102
#define PDKIM_ERR_LONG_LINE        -103
#define PDKIM_ERR_BUFFER_TOO_SMALL -104
#define PDKIM_ERR_EXCESS_SIGS	   -105
#define PDKIM_SIGN_PRIVKEY_WRAP    -106
#define PDKIM_SIGN_PRIVKEY_B64D    -107

/* -------------------------------------------------------------------------- */
/* Main/Extended verification status */
#define PDKIM_VERIFY_NONE      0
#define PDKIM_VERIFY_INVALID   1
#define PDKIM_VERIFY_FAIL      2
#define PDKIM_VERIFY_PASS      3
#define PDKIM_VERIFY_POLICY    BIT(31)

#define PDKIM_VERIFY_FAIL_BODY                    1
#define PDKIM_VERIFY_FAIL_MESSAGE                 2
#define PDKIM_VERIFY_FAIL_SIG_ALGO_MISMATCH	  3
#define PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE   4
#define PDKIM_VERIFY_INVALID_BUFFER_SIZE          5
#define PDKIM_VERIFY_INVALID_PUBKEY_DNSRECORD     6
#define PDKIM_VERIFY_INVALID_PUBKEY_IMPORT        7
#define PDKIM_VERIFY_INVALID_SIGNATURE_ERROR      8
#define PDKIM_VERIFY_INVALID_DKIM_VERSION         9

/* -------------------------------------------------------------------------- */
/* Some parameter values */
#define PDKIM_QUERYMETHOD_DNS_TXT 0

/*#define PDKIM_ALGO_RSA_SHA256     0 */
/*#define PDKIM_ALGO_RSA_SHA1       1 */

#define PDKIM_CANON_SIMPLE        0
#define PDKIM_CANON_RELAXED       1

/* -------------------------------------------------------------------------- */
/* Some required forward declarations, please ignore */
typedef struct pdkim_stringlist pdkim_stringlist;
typedef struct pdkim_str pdkim_str;
typedef struct sha1_context sha1_context;
typedef struct sha2_context sha2_context;
#define HAVE_SHA1_CONTEXT
#define HAVE_SHA2_CONTEXT

/* -------------------------------------------------------------------------- */
/* Some concessions towards Redmond */
#ifdef WINDOWS
#define snprintf _snprintf
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif


/* -------------------------------------------------------------------------- */
/* Public key as (usually) fetched from DNS */
typedef struct pdkim_pubkey {
  const uschar * version;         /* v=  */
  const uschar *granularity;      /* g=  */

  const uschar * hashes;          /* h=  */
  const uschar * keytype;         /* k=  */
  const uschar * srvtype;         /* s=  */
  uschar *notes;                  /* n=  */

  blob  key;                      /* p=  */
  int   testing;                  /* t=y */
  int   no_subdomaining;          /* t=s */
} pdkim_pubkey;

/* -------------------------------------------------------------------------- */
/* Body-hash to be calculated */
typedef struct pdkim_bodyhash {
  struct pdkim_bodyhash *	next;
  int				hashtype;
  int 				canon_method;
  long				bodylength;

  hctx         			body_hash_ctx;
  unsigned long			signed_body_bytes;	/* done so far */
  int				num_buffered_blanklines;

  blob				bh;			/* completed hash */
} pdkim_bodyhash;

/* -------------------------------------------------------------------------- */
/* Signature as it appears in a DKIM-Signature header */
typedef struct pdkim_signature {
  struct pdkim_signature * next;

  /* Bits stored in a DKIM signature header --------------------------- */

  /* (v=) The version, as an integer. Currently, always "1" */
  int version;

  /* (a=) The signature algorithm. Either PDKIM_ALGO_RSA_SHA256 */
  int keytype;	/* pdkim_keytypes index */
  int hashtype;	/* pdkim_hashes index */

  /* (c=x/) Header canonicalization method. Either PDKIM_CANON_SIMPLE
     or PDKIM_CANON_RELAXED */
  int canon_headers;

  /* (c=/x) Body canonicalization method. Either PDKIM_CANON_SIMPLE
     or PDKIM_CANON_RELAXED */
  int canon_body;

  /* (q=) Query Method. Currently, only PDKIM_QUERYMETHOD_DNS_TXT
     is specified */
  int querymethod;

  /* (s=) The selector string as given in the signature */
  uschar *selector;

  /* (d=) The domain as given in the signature */
  uschar *domain;

  /* (i=) The identity as given in the signature */
  uschar *identity;

  /* (t=) Timestamp of signature creation */
  unsigned long created;

  /* (x=) Timestamp of expiry of signature */
  unsigned long expires;

  /* (l=) Amount of hashed body bytes (after canonicalization). Default
     is -1. Note: a value of 0 means that the body is unsigned! */
  long bodylength;

  /* (h=) Colon-separated list of header names that are included in the
     signature */
  uschar *headernames;

  /* (z=) */
  uschar *copiedheaders;

  /* (b=) Raw signature data, along with its length in bytes */
  blob sighash;

  /* (bh=) Raw body hash data, along with its length in bytes */
  blob bodyhash;

  /* Folded DKIM-Signature: header. Signing only, NULL for verifying.
     Ready for insertion into the message. Note: Folded using CRLFTB,
     but final line terminator is NOT included. Note2: This buffer is
     free()d when you call pdkim_free_ctx(). */
  uschar *signature_header;

  /* The main verification status. Verification only. One of:

     PDKIM_VERIFY_NONE      Verification was not attempted. This status
                            should not appear.

     PDKIM_VERIFY_INVALID   There was an error while trying to verify
                            the signature. A more precise description
                            is available in verify_ext_status.

     PDKIM_VERIFY_FAIL      Verification failed because either the body
                            hash did not match, or the signature verification
                            failed. This means the message was modified.
                            Check verify_ext_status for the exact reason.

     PDKIM_VERIFY_PASS      Verification succeeded.
  */
  int verify_status;

  /* Extended verification status. Verification only. Depending on the value
     of verify_status, it can contain:

     For verify_status == PDKIM_VERIFY_INVALID:

        PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE
          Unable to retrieve a public key container.

        PDKIM_VERIFY_INVALID_BUFFER_SIZE
          Either the DNS name constructed to retrieve the public key record
          does not fit into PDKIM_DNS_TXT_MAX_NAMELEN bytes, or the retrieved
          record is longer than PDKIM_DNS_TXT_MAX_RECLEN bytes.

        PDKIM_VERIFY_INVALID_PUBKEY_PARSING
          (Syntax) error while parsing the retrieved public key record.


     For verify_status == PDKIM_VERIFY_FAIL:

        PDKIM_VERIFY_FAIL_BODY
          The calculated body hash does not match the advertised body hash
          from the bh= tag of the signature.

        PDKIM_VERIFY_FAIL_MESSAGE
          RSA verification of the signature (b= tag) failed.
  */
  int verify_ext_status;

  /* Pointer to a public key record that was used to verify the signature.
     See pdkim_pubkey declaration above for more information.
     Caution: is NULL if signing or if no record was retrieved. */
  pdkim_pubkey *pubkey;

  /* Properties below this point are used internally only ------------- */

  /* Per-signature helper variables ----------------------------------- */
  pdkim_bodyhash *calc_body_hash;	/* hash to be / being calculated */

  pdkim_stringlist *headers;		/* Raw headers included in the sig */

  /* Signing specific ------------------------------------------------- */
  uschar * privkey;	     /* Private key                                 */
  uschar * sign_headers;    /* To-be-signed header names                   */
  uschar * rawsig_no_b_val; /* Original signature header w/o b= tag value. */
} pdkim_signature;


/* -------------------------------------------------------------------------- */
/* Context to keep state between all operations. */
typedef struct pdkim_ctx {

#define PDKIM_MODE_SIGN   BIT(0)	/* if unset, mode==verify */
#define PDKIM_DOT_TERM	  BIT(1)	/* dot termination and unstuffing */
#define PDKIM_SEEN_CR	  BIT(2)
#define PDKIM_SEEN_LF	  BIT(3)
#define PDKIM_PAST_HDRS	  BIT(4)
#define PDKIM_SEEN_EOD	  BIT(5)
  unsigned   flags;

  /* One (signing) or several chained (verification) signatures */
  pdkim_signature *sig;

  /* One (signing) or several chained (verification) bodyhashes */
  pdkim_bodyhash *bodyhash;

  /* Callback for dns/txt query method (verification only) */
  uschar * (*dns_txt_callback)(uschar *);

  /* Coder's little helpers */
  gstring   *cur_header;
  uschar    *linebuf;
  int        linebuf_offset;
  int        num_headers;
  pdkim_stringlist *headers; /* Raw headers for verification         */
} pdkim_ctx;


/******************************************************************************/

typedef struct {
  const uschar * dkim_hashname;
  hashmethod	 exim_hashmethod;
} pdkim_hashtype;
extern const pdkim_hashtype pdkim_hashes[];

/******************************************************************************/


/* -------------------------------------------------------------------------- */
/* API functions. Please see the sample code in sample/test_sign.c and
   sample/test_verify.c for documentation.
*/

#ifdef __cplusplus
extern "C" {
#endif

void	   pdkim_init         (void);

void	   pdkim_init_context (pdkim_ctx *, BOOL, uschar * (*)(uschar *));

DLLEXPORT
pdkim_signature *pdkim_init_sign    (pdkim_ctx *,
			       uschar *, uschar *, uschar *, uschar *,
			       const uschar **);

DLLEXPORT
pdkim_ctx *pdkim_init_verify  (uschar * (*)(uschar *), BOOL);

DLLEXPORT
void       pdkim_set_optional (pdkim_signature *, char *, char *,int, int,
                               long,
                               unsigned long,
                               unsigned long);

int		pdkim_hashname_to_hashtype(const uschar *, unsigned);
void		pdkim_cstring_to_canons(const uschar *, unsigned, int *, int *);
pdkim_bodyhash *pdkim_set_bodyhash(pdkim_ctx *, int, int, long);
pdkim_bodyhash *pdkim_set_sig_bodyhash(pdkim_ctx *, pdkim_signature *);

DLLEXPORT
int        pdkim_feed         (pdkim_ctx *, uschar *, int);
DLLEXPORT
int        pdkim_feed_finish  (pdkim_ctx *, pdkim_signature **, const uschar **);

DLLEXPORT
void       pdkim_free_ctx     (pdkim_ctx *);


const uschar *	pdkim_errstr(int);

extern uschar *		pdkim_encode_base64(blob *);
extern void		pdkim_decode_base64(const uschar *, blob *);
extern void		pdkim_hexprint(const uschar *, int);
extern void		pdkim_quoteprint(const uschar *, int);
extern pdkim_pubkey *	pdkim_parse_pubkey_record(const uschar *);
extern uschar *		pdkim_relax_header_n(const uschar *, int, BOOL);
extern uschar *		pdkim_relax_header(const uschar *, BOOL);
extern uschar *		dkim_sig_to_a_tag(const pdkim_signature *);

#ifdef __cplusplus
}
#endif

#endif
