/* Copyright (C) 2012,2016 Phil Pennock.
 * This is distributed as part of Exim and licensed under the GPL.
 * See the file "NOTICE" for more details.
 */

/* Build with:
 * c99 $(pkg-config --cflags openssl) gen_pkcs3.c $(pkg-config --libs openssl)
 */

/*
 * Rationale:
 * The Diffie-Hellman primes which are embedded into Exim as named primes for
 * the tls_dhparam option are in the std-crypto.c file.  The source for those
 * comes from various RFCs, where they are given in hexadecimal form.
 *
 * This tool provides convenient conversion, to reduce the risk of human
 * error in transcription.
 */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/pem.h>

extern const char *__progname;


void __attribute__((__noreturn__)) __attribute__((__format__(printf, 1, 2)))
die(const char *fmt, ...)
{
  va_list ap;

  fflush(NULL);
  fprintf(stderr, "%s: ", __progname);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
  fflush(stderr);
  exit(1);
}


void __attribute__((__noreturn__))
die_openssl_err(const char *msg)
{
  char err_string[250];
  unsigned long e;

  ERR_error_string_n(ERR_get_error(), err_string, sizeof(err_string));
  die("%s: %s", msg, err_string);
}


static BIGNUM *
bn_from_text(const char *text)
{
  BIGNUM *b;
  char *p, *spaceless;
  const char *q, *end;
  size_t len;
  int rc;

  len = strlen(text);
  spaceless = malloc(len);
  if (!spaceless)
    die("malloc(%zu) failed: %s", len, strerror(errno));

  for (p = spaceless, q = text, end = text + len;
       q < end;
       ++q) {
    if (!isspace(*q))
      *p++ = *q;
  }

  b = NULL;
  rc = BN_hex2bn(&b, spaceless);

  if (rc != p - spaceless)
    die("BN_hex2bn did not convert entire input; took %d of %zu bytes",
        rc, p - spaceless);

  return b;
}


static void
our_dh_check(DH *dh)
{
  int rc, errflags = 0;

  rc = DH_check(dh, &errflags);
  if (!rc) die_openssl_err("DH_check() could not be performed");;

  /* We ignore DH_UNABLE_TO_CHECK_GENERATOR because some of the invocations
   * deliberately provide generators other than 2 or 5. */

  if (errflags & DH_CHECK_P_NOT_SAFE_PRIME)
    die("DH_check(): p not a safe prime");
  if (errflags & DH_NOT_SUITABLE_GENERATOR)
    die("DH_check(): g not suitable as generator");
}


static void
emit_c_format_dh(FILE *stream, DH *dh)
{
  BIO *bio;
  long length;
  char *data, *end, *p, *nl;

  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_DHparams(bio, dh);
  length = BIO_get_mem_data(bio, &data);
  if (!length)
    die("no data in memory BIO to format for printing");
  if (length < 0)
    die("grr, negative length memory not supported");
  end = data + length;

  for (p = data; p < end; /**/) {
    nl = strchr(p, '\n');
    if (!nl) {
      fprintf(stream, "\"%s\\n\"\n/* missing final newline */\n", p);
      break;
    }
    *nl = '\0';
    fprintf(stream, "\"%s\\n\"%s\n", p, (nl == end - 1 ? ";" : ""));
    p = nl + 1;
  }
}


void __attribute__((__noreturn__))
usage(FILE *stream, int exitcode)
{
  fprintf(stream, "Usage: %s [-CPcst] <dh_p> <dh_g> [<dh_q>]\n"
"Both dh_p and dh_g should be hex strings representing the numbers\n"
"The same applies to the optional dh_q (prime-order subgroup).\n"
"They may contain whitespace.\n"
"Older values, dh_g is often just '2', not a long string.\n"
"\n"
" -C      show C string form of PEM result\n"
" -P      do not show PEM\n"
" -c      run OpenSSL DH_check() on the DH object\n"
" -s      show the parsed p and g\n"
" -t      show text form of certificate\n"

      , __progname);
  exit(exitcode);
}


int
main(int argc, char *argv[])
{
  BIGNUM *p, *g, *q;
  DH *dh;
  int ch;
  bool perform_dh_check = false;
  bool show_c_form = false;
  bool show_numbers = false;
  bool show_pem = true;
  bool show_text = false;
  bool given_q = false;

  while ((ch = getopt(argc, argv, "CPcsth")) != -1) {
    switch (ch) {
      case 'C':
        show_c_form = true;
        break;
      case 'P':
        show_pem = false;
        break;
      case 'c':
        perform_dh_check = true;
        break;
      case 's':
        show_numbers = true;
        break;
      case 't':
        show_text = true;
        break;

      case 'h':
        usage(stdout, 0);
      case '?':
        die("Unknown option or missing argument -%c", optopt);
      default:
        die("Unhandled option -%c", ch);
    }
  }

  optind -= 1;
  argc -= optind;
  argv += optind;

  if ((argc < 3) || (argc > 4)) {
    fprintf(stderr, "argc: %d\n", argc);
    usage(stderr, 1);
  }

  // If we use DH_set0_pqg instead of setting dh fields directly; the q value
  // is optional and may be NULL.
  // Just blank them all.
  p = g = q = NULL;

  p = bn_from_text(argv[1]);
  g = bn_from_text(argv[2]);
  if (argc >= 4) {
    q = bn_from_text(argv[3]);
    given_q = true;
  }

  if (show_numbers) {
    printf("p = ");
    BN_print_fp(stdout, p);
    printf("\ng = ");
    BN_print_fp(stdout, g);
    if (given_q) {
      printf("\nq = ");
      BN_print_fp(stdout, q);
    }
    printf("\n");
  }

  dh = DH_new();
  // The documented method for setting q appeared in OpenSSL 1.1.0.
#if OPENSSL_VERSION_NUMBER >= 0x1010000f
  // NULL okay for q; yes, the optional value is in the middle.
  if (DH_set0_pqg(dh, p, q, g) != 1) {
    die_openssl_err("initialising DH pqg values failed");
  }
#else
  dh->p = p;
  dh->g = g;
  if (given_q) {
    dh->q = q;
  }
#endif

  if (perform_dh_check)
    our_dh_check(dh);

  if (show_text)
    DHparams_print_fp(stdout, dh);

  if (show_pem) {
    if (show_c_form)
      emit_c_format_dh(stdout, dh);
    else
      PEM_write_DHparams(stdout, dh);
  }

  DH_free(dh); /* should free p,g (& q if non-NULL) too */
  return 0;
}
