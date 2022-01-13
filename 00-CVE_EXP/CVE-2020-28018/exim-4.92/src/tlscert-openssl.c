/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Jeremy Harris 2014 - 2018 */

/* This module provides TLS (aka SSL) support for Exim using the OpenSSL
library. It is #included into the tls.c file when that library is used.
*/


/* Heading stuff */

#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
# define EXIM_HAVE_ASN1_MACROS
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
# define ASN1_STRING_get0_data ASN1_STRING_data
#endif

/*****************************************************
*  Export/import a certificate, binary/printable
*****************************************************/
int
tls_export_cert(uschar * buf, size_t buflen, void * cert)
{
BIO * bp = BIO_new(BIO_s_mem());
int fail;

if ((fail = PEM_write_bio_X509(bp, (X509 *)cert) ? 0 : 1))
  log_write(0, LOG_MAIN, "TLS error in certificate export: %s",
    ERR_error_string(ERR_get_error(), NULL));
else
  {
  char * cp = CS buf;
  int n;
  buflen -= 2;
  for(;;)
    {
    if ((n = BIO_gets(bp, cp, (int)buflen)) <= 0) break;
    cp += n+1;
    buflen -= n+1;
    cp[-2] = '\\'; cp[-1] = 'n'; /* newline->"\n" */
    }				 /* compat with string_printing() */
  *cp = '\0';
  }

BIO_free(bp);
return fail;
}

int
tls_import_cert(const uschar * buf, void ** cert)
{
void * reset_point = store_get(0);
const uschar * cp = string_unprinting(US buf);
BIO * bp;
X509 * x = *(X509 **)cert;
int fail = 0;

if (x) X509_free(x);

bp = BIO_new_mem_buf(US cp, -1);
if (!(x = PEM_read_bio_X509(bp, NULL, 0, NULL)))
  {
  log_write(0, LOG_MAIN, "TLS error in certificate import: %s",
    ERR_error_string(ERR_get_error(), NULL));
  fail = 1;
  }
else
  *cert = (void *)x;
BIO_free(bp);
store_reset(reset_point);
return fail;
}

void
tls_free_cert(void ** cert)
{
X509 * x = *(X509 **)cert;
if (x)
  {
  X509_free(x);
  *cert = NULL;
  }
}


/*****************************************************
*  Certificate field extraction routines
*****************************************************/

/* First, some internal service functions */

static uschar *
badalloc(void)
{
expand_string_message = US"allocation failure";
return NULL;
}

static uschar *
bio_string_copy(BIO * bp, int len)
{
uschar * cp = US"";
len = len > 0 ? (int) BIO_get_mem_data(bp, &cp) : 0;
cp = string_copyn(cp, len);
BIO_free(bp);
return cp;
}

static uschar *
asn1_time_copy(const ASN1_TIME * asntime, uschar * mod)
{
uschar * s = NULL;
BIO * bp = BIO_new(BIO_s_mem());
int len;

if (!bp)
  return badalloc();
len = ASN1_TIME_print(bp, asntime);
len = len > 0 ? (int) BIO_get_mem_data(bp, CSS &s) : 0;

if (mod && Ustrcmp(mod, "raw") == 0)		/* native ASN */
  s = string_copyn(s, len);
else
  {
  struct tm tm;
  struct tm * tm_p = &tm;
  BOOL mod_tz = TRUE;
  uschar * tz = to_tz(US"GMT0");    /* need to call strptime with baseline TZ */

  /* Parse OpenSSL ASN1_TIME_print output.  A shame there seems to
  be no other interface for the times.
  */

  /*XXX %Z might be glibc-specific?  Solaris has it, at least*/
  /*XXX should we switch to POSIX locale for this? */
  tm.tm_isdst = 0;
  if (!len || !strptime(CCS s, "%b %e %T %Y %Z", &tm))
    expand_string_message = US"failed time conversion";

  else
    {
    time_t t = mktime(&tm);	/* make the tm self-consistent */

    if (mod && Ustrcmp(mod, "int") == 0)	/* seconds since epoch */
      s = string_sprintf(TIME_T_FMT, t);

    else
      {
      if (!f.timestamps_utc)	/* decoded string in local TZ */
	{				/* shift to local TZ */
	restore_tz(tz);
	mod_tz = FALSE;
	tm_p = localtime(&t);
	}
      /* "utc" is default, and rfc5280 says cert times should be Zulu */

      /* convert to string in our format */
      len = 32;
      s = store_get(len);
      strftime(CS s, (size_t)len, "%b %e %T %Y %z", tm_p);
      }
    }

  if (mod_tz)
    restore_tz(tz);
  }
BIO_free(bp);
return s;
}

static uschar *
x509_name_copy(X509_NAME * name)
{
BIO * bp = BIO_new(BIO_s_mem());
int len_good;

if (!bp) return badalloc();

len_good =
  X509_NAME_print_ex(bp, name, 0, XN_FLAG_RFC2253) >= 0
  ? 1 : 0;
return bio_string_copy(bp, len_good);
}

/**/
/* Now the extractors, called from expand.c
Arguments:
  cert		The certificate
  mod		Optional modifiers for the operator

Return:
  Allocated string with extracted value
*/

uschar *
tls_cert_issuer(void * cert, uschar * mod)
{
uschar * cp = x509_name_copy(X509_get_issuer_name((X509 *)cert));
return mod ? tls_field_from_dn(cp, mod) : cp;
}

uschar *
tls_cert_not_before(void * cert, uschar * mod)
{
return asn1_time_copy(X509_get_notBefore((X509 *)cert), mod);
}

uschar *
tls_cert_not_after(void * cert, uschar * mod)
{
return asn1_time_copy(X509_get_notAfter((X509 *)cert), mod);
}

uschar *
tls_cert_serial_number(void * cert, uschar * mod)
{
uschar txt[256];
BIO * bp = BIO_new(BIO_s_mem());
int len;

if (!bp) return badalloc();

len = i2a_ASN1_INTEGER(bp, X509_get_serialNumber((X509 *)cert));
if (len < sizeof(txt))
  BIO_read(bp, txt, len);
else
  len = 0;
BIO_free(bp);
return string_copynlc(txt, len);	/* lowercase */
}

uschar *
tls_cert_signature(void * cert, uschar * mod)
{
uschar * cp = NULL;
BIO * bp = BIO_new(BIO_s_mem());

if (!bp) return badalloc();

if (X509_print_ex(bp, (X509 *)cert, 0,
  X509_FLAG_NO_HEADER | X509_FLAG_NO_VERSION | X509_FLAG_NO_SERIAL |
  X509_FLAG_NO_SIGNAME | X509_FLAG_NO_ISSUER | X509_FLAG_NO_VALIDITY |
  X509_FLAG_NO_SUBJECT | X509_FLAG_NO_PUBKEY | X509_FLAG_NO_EXTENSIONS |
  /* X509_FLAG_NO_SIGDUMP is the missing one */
  X509_FLAG_NO_AUX) == 1)
  {
  long len = BIO_get_mem_data(bp, &cp);

  /* Strip leading "Signature Algorithm" line */
  while (*cp && *cp != '\n') { cp++; len--; }

  cp = string_copyn(cp+1, len-1);
  }
BIO_free(bp);
return cp;
}

uschar *
tls_cert_signature_algorithm(void * cert, uschar * mod)
{
uschar * cp = NULL;
BIO * bp = BIO_new(BIO_s_mem());

if (!bp) return badalloc();

if (X509_print_ex(bp, (X509 *)cert, 0,
  X509_FLAG_NO_HEADER | X509_FLAG_NO_VERSION | X509_FLAG_NO_SERIAL |
  /* X509_FLAG_NO_SIGNAME is the missing one */
  X509_FLAG_NO_ISSUER | X509_FLAG_NO_VALIDITY |
  X509_FLAG_NO_SUBJECT | X509_FLAG_NO_PUBKEY | X509_FLAG_NO_EXTENSIONS |
  X509_FLAG_NO_SIGDUMP | X509_FLAG_NO_AUX) == 1)
  {
  long len = BIO_get_mem_data(bp, &cp);

  /* Strip leading "    Signature Algorithm: " and trailing newline */
  while (*cp && *cp != ':') { cp++; len--; }
  do { cp++; len--; } while (*cp && *cp == ' ');
  if (cp[len-1] == '\n') len--;

  cp = string_copyn(cp, len);
  }
BIO_free(bp);
return cp;
}

uschar *
tls_cert_subject(void * cert, uschar * mod)
{
uschar * cp = x509_name_copy(X509_get_subject_name((X509 *)cert));
return mod ? tls_field_from_dn(cp, mod) : cp;
}

uschar *
tls_cert_version(void * cert, uschar * mod)
{
return string_sprintf("%ld", X509_get_version((X509 *)cert));
}

uschar *
tls_cert_ext_by_oid(void * cert, uschar * oid, int idx)
{
int nid = OBJ_create(CS oid, "", "");
int nidx = X509_get_ext_by_NID((X509 *)cert, nid, idx);
X509_EXTENSION * ex = X509_get_ext((X509 *)cert, nidx);
ASN1_OCTET_STRING * adata = X509_EXTENSION_get_data(ex);
BIO * bp = BIO_new(BIO_s_mem());
long len;
uschar * cp1;
uschar * cp2;
uschar * cp3;

if (!bp) return badalloc();

#ifdef EXIM_HAVE_ASN1_MACROS
ASN1_STRING_print(bp, adata);
#else
M_ASN1_OCTET_STRING_print(bp, adata);
#endif

/* binary data, DER encoded */
/* just dump for now */
len = BIO_get_mem_data(bp, &cp1);
cp3 = cp2 = store_get(len*3+1);

while(len)
  {
  cp2 += sprintf(CS cp2, "%.2x ", *cp1++);
  len--;
  }
cp2[-1] = '\0';

return cp3;
}

uschar *
tls_cert_subject_altname(void * cert, uschar * mod)
{
gstring * list = NULL;
STACK_OF(GENERAL_NAME) * san = (STACK_OF(GENERAL_NAME) *)
  X509_get_ext_d2i((X509 *)cert, NID_subject_alt_name, NULL, NULL);
uschar osep = '\n';
uschar * tag = US"";
uschar * ele;
int match = -1;
int len;

if (!san) return NULL;

while (mod && *mod)
  {
  if (*mod == '>' && *++mod) osep = *mod++;
  else if (Ustrncmp(mod,"dns",3)==0) { match = GEN_DNS; mod += 3; }
  else if (Ustrncmp(mod,"uri",3)==0) { match = GEN_URI; mod += 3; }
  else if (Ustrncmp(mod,"mail",4)==0) { match = GEN_EMAIL; mod += 4; }
  else mod++;

  if (*mod == ',') mod++;
  }

while (sk_GENERAL_NAME_num(san) > 0)
  {
  GENERAL_NAME * namePart = sk_GENERAL_NAME_pop(san);
  if (match != -1 && match != namePart->type)
    continue;
  switch (namePart->type)
    {
    case GEN_DNS:
      tag = US"DNS";
      ele = US ASN1_STRING_get0_data(namePart->d.dNSName);
      len = ASN1_STRING_length(namePart->d.dNSName);
      break;
    case GEN_URI:
      tag = US"URI";
      ele = US ASN1_STRING_get0_data(namePart->d.uniformResourceIdentifier);
      len = ASN1_STRING_length(namePart->d.uniformResourceIdentifier);
      break;
    case GEN_EMAIL:
      tag = US"MAIL";
      ele = US ASN1_STRING_get0_data(namePart->d.rfc822Name);
      len = ASN1_STRING_length(namePart->d.rfc822Name);
      break;
    default:
      continue;	/* ignore unrecognised types */
    }
  if (ele[len])	/* not nul-terminated */
    ele = string_copyn(ele, len);

  if (Ustrlen(ele) == len)	/* ignore any with embedded nul */
    list = string_append_listele(list, osep,
	  match == -1 ? string_sprintf("%s=%s", tag, ele) : ele);
  }

sk_GENERAL_NAME_free(san);
return string_from_gstring(list);
}

uschar *
tls_cert_ocsp_uri(void * cert, uschar * mod)
{
STACK_OF(ACCESS_DESCRIPTION) * ads = (STACK_OF(ACCESS_DESCRIPTION) *)
  X509_get_ext_d2i((X509 *)cert, NID_info_access, NULL, NULL);
int adsnum = sk_ACCESS_DESCRIPTION_num(ads);
int i;
uschar sep = '\n';
gstring * list = NULL;

if (mod)
  if (*mod == '>' && *++mod) sep = *mod++;

for (i = 0; i < adsnum; i++)
  {
  ACCESS_DESCRIPTION * ad = sk_ACCESS_DESCRIPTION_value(ads, i);

  if (ad && OBJ_obj2nid(ad->method) == NID_ad_OCSP)
    list = string_append_listele_n(list, sep,
      US ASN1_STRING_get0_data(ad->location->d.ia5),
      ASN1_STRING_length(ad->location->d.ia5));
  }
sk_ACCESS_DESCRIPTION_free(ads);
return string_from_gstring(list);
}

uschar *
tls_cert_crl_uri(void * cert, uschar * mod)
{
STACK_OF(DIST_POINT) * dps = (STACK_OF(DIST_POINT) *)
  X509_get_ext_d2i((X509 *)cert,  NID_crl_distribution_points,
    NULL, NULL);
DIST_POINT * dp;
int dpsnum = sk_DIST_POINT_num(dps);
int i;
uschar sep = '\n';
gstring * list = NULL;

if (mod)
  if (*mod == '>' && *++mod) sep = *mod++;

if (dps) for (i = 0; i < dpsnum; i++)
  if ((dp = sk_DIST_POINT_value(dps, i)))
    {
    STACK_OF(GENERAL_NAME) * names = dp->distpoint->name.fullname;
    GENERAL_NAME * np;
    int nnum = sk_GENERAL_NAME_num(names);
    int j;

    for (j = 0; j < nnum; j++)
      if (  (np = sk_GENERAL_NAME_value(names, j))
	 && np->type == GEN_URI
	 )
	list = string_append_listele_n(list, sep,
	  US ASN1_STRING_get0_data(np->d.uniformResourceIdentifier),
	  ASN1_STRING_length(np->d.uniformResourceIdentifier));
    }
sk_DIST_POINT_free(dps);
return string_from_gstring(list);
}



/*****************************************************
*  Certificate operator routines
*****************************************************/
uschar *
tls_cert_der_b64(void * cert)
{
BIO * bp = BIO_new(BIO_s_mem());
uschar * cp = NULL;

if (!i2d_X509_bio(bp, (X509 *)cert))
  log_write(0, LOG_MAIN, "TLS error in certificate export: %s",
    ERR_error_string(ERR_get_error(), NULL));
else
  {
  long len = BIO_get_mem_data(bp, &cp);
  cp = b64encode(cp, (int)len);
  }

BIO_free(bp);
return cp;
}


static uschar *
fingerprint(X509 * cert, const EVP_MD * fdig)
{
int j;
unsigned int n;
uschar md[EVP_MAX_MD_SIZE];
uschar * cp;

if (!X509_digest(cert,fdig,md,&n))
  {
  expand_string_message = US"tls_cert_fprt: out of mem\n";
  return NULL;
  }
cp = store_get(n*2+1);
for (j = 0; j < (int)n; j++) sprintf(CS cp+2*j, "%02X", md[j]);
return(cp);
}

uschar *
tls_cert_fprt_md5(void * cert)
{
return fingerprint((X509 *)cert, EVP_md5());
}

uschar *
tls_cert_fprt_sha1(void * cert)
{
return fingerprint((X509 *)cert, EVP_sha1());
}

uschar *
tls_cert_fprt_sha256(void * cert)
{
return fingerprint((X509 *)cert, EVP_sha256());
}


/* vi: aw ai sw=2
*/
/* End of tlscert-openssl.c */
