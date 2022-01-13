/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */


/* The stand-alone version just tests the algorithm. We have to drag
in the MD5 computation functions, without their own stand-alone main
program. */

#ifdef STAND_ALONE
#define CRAM_STAND_ALONE
#include "md5.c"


/* This is the normal, non-stand-alone case */

#else
#include "../exim.h"
#include "cram_md5.h"

/* Options specific to the cram_md5 authentication mechanism. */

optionlist auth_cram_md5_options[] = {
  { "client_name",        opt_stringptr,
      (void *)(offsetof(auth_cram_md5_options_block, client_name)) },
  { "client_secret",      opt_stringptr,
      (void *)(offsetof(auth_cram_md5_options_block, client_secret)) },
  { "server_secret",      opt_stringptr,
      (void *)(offsetof(auth_cram_md5_options_block, server_secret)) }
};

/* Size of the options list. An extern variable has to be used so that its
address can appear in the tables drtables.c. */

int auth_cram_md5_options_count =
  sizeof(auth_cram_md5_options)/sizeof(optionlist);

/* Default private options block for the condition authentication method. */

auth_cram_md5_options_block auth_cram_md5_option_defaults = {
  NULL,             /* server_secret */
  NULL,             /* client_secret */
  NULL              /* client_name */
};


#ifdef MACRO_PREDEF

/* Dummy values */
void auth_cram_md5_init(auth_instance *ablock) {}
int auth_cram_md5_server(auth_instance *ablock, uschar *data) {return 0;}
int auth_cram_md5_client(auth_instance *ablock, void *sx, int timeout,
    uschar *buffer, int buffsize) {return 0;}

#else	/*!MACRO_PREDEF*/


/*************************************************
*          Initialization entry point            *
*************************************************/

/* Called for each instance, after its options have been read, to
enable consistency checks to be done, or anything else that needs
to be set up. */

void
auth_cram_md5_init(auth_instance *ablock)
{
auth_cram_md5_options_block *ob =
  (auth_cram_md5_options_block *)(ablock->options_block);
if (ob->server_secret != NULL) ablock->server = TRUE;
if (ob->client_secret != NULL)
  {
  ablock->client = TRUE;
  if (ob->client_name == NULL) ob->client_name = primary_hostname;
  }
}

#endif	/*!MACRO_PREDEF*/
#endif  /* STAND_ALONE */



#ifndef MACRO_PREDEF
/*************************************************
*      Perform the CRAM-MD5 algorithm            *
*************************************************/

/* The CRAM-MD5 algorithm is described in RFC 2195. It computes

  MD5((secret XOR opad), MD5((secret XOR ipad), challenge))

where secret is padded out to 64 characters (after being reduced to an MD5
digest if longer than 64) and ipad and opad are 64-byte strings of 0x36 and
0x5c respectively, and comma means concatenation.

Arguments:
  secret         the shared secret
  challenge      the challenge text
  digest         16-byte slot to put the answer in

Returns:         nothing
*/

static void
compute_cram_md5(uschar *secret, uschar *challenge, uschar *digestptr)
{
md5 base;
int i;
int len = Ustrlen(secret);
uschar isecret[64];
uschar osecret[64];
uschar md5secret[16];

/* If the secret is longer than 64 characters, we compute its MD5 digest
and use that. */

if (len > 64)
  {
  md5_start(&base);
  md5_end(&base, US secret, len, md5secret);
  secret = US md5secret;
  len = 16;
  }

/* The key length is now known to be <= 64. Set up the padded and xor'ed
versions. */

memcpy(isecret, secret, len);
memset(isecret+len, 0, 64-len);
memcpy(osecret, isecret, 64);

for (i = 0; i < 64; i++)
  {
  isecret[i] ^= 0x36;
  osecret[i] ^= 0x5c;
  }

/* Compute the inner MD5 digest */

md5_start(&base);
md5_mid(&base, isecret);
md5_end(&base, US challenge, Ustrlen(challenge), md5secret);

/* Compute the outer MD5 digest */

md5_start(&base);
md5_mid(&base, osecret);
md5_end(&base, md5secret, 16, digestptr);
}


#ifndef STAND_ALONE

/*************************************************
*             Server entry point                 *
*************************************************/

/* For interface, see auths/README */

int
auth_cram_md5_server(auth_instance *ablock, uschar *data)
{
auth_cram_md5_options_block *ob =
  (auth_cram_md5_options_block *)(ablock->options_block);
uschar *challenge = string_sprintf("<%d.%ld@%s>", getpid(),
    (long int) time(NULL), primary_hostname);
uschar *clear, *secret;
uschar digest[16];
int i, rc, len;

/* If we are running in the test harness, always send the same challenge,
an example string taken from the RFC. */

if (f.running_in_test_harness)
  challenge = US"<1896.697170952@postoffice.reston.mci.net>";

/* No data should have been sent with the AUTH command */

if (*data != 0) return UNEXPECTED;

/* Send the challenge, read the return */

if ((rc = auth_get_data(&data, challenge, Ustrlen(challenge))) != OK) return rc;
if ((len = b64decode(data, &clear)) < 0) return BAD64;

/* The return consists of a user name, space-separated from the CRAM-MD5
digest, expressed in hex. Extract the user name and put it in $auth1 and $1.
The former is now the preferred variable; the latter is the original one. Then
check that the remaining length is 32. */

auth_vars[0] = expand_nstring[1] = clear;
while (*clear != 0 && !isspace(*clear)) clear++;
if (!isspace(*clear)) return FAIL;
*clear++ = 0;

expand_nlength[1] = clear - expand_nstring[1] - 1;
if (len - expand_nlength[1] - 1 != 32) return FAIL;
expand_nmax = 1;

/* Expand the server_secret string so that it can compute a value dependent on
the user name if necessary. */

debug_print_string(ablock->server_debug_string);    /* customized debugging */
secret = expand_string(ob->server_secret);

/* A forced fail implies failure of authentication - i.e. we have no secret for
the given name. */

if (secret == NULL)
  {
  if (f.expand_string_forcedfail) return FAIL;
  auth_defer_msg = expand_string_message;
  return DEFER;
  }

/* Compute the CRAM-MD5 digest that we should have received from the client. */

compute_cram_md5(secret, challenge, digest);

HDEBUG(D_auth)
  {
  uschar buff[64];
  debug_printf("CRAM-MD5: user name = %s\n", auth_vars[0]);
  debug_printf("          challenge = %s\n", challenge);
  debug_printf("          received  = %s\n", clear);
  Ustrcpy(buff,"          digest    = ");
  for (i = 0; i < 16; i++) sprintf(CS buff+22+2*i, "%02x", digest[i]);
  debug_printf("%.54s\n", buff);
  }

/* We now have to compare the digest, which is 16 bytes in binary, with the
data received, which is expressed in lower case hex. We checked above that
there were 32 characters of data left. */

for (i = 0; i < 16; i++)
  {
  int a = *clear++;
  int b = *clear++;
  if (((((a >= 'a')? a - 'a' + 10 : a - '0') << 4) +
        ((b >= 'a')? b - 'a' + 10 : b - '0')) != digest[i]) return FAIL;
  }

/* Expand server_condition as an authorization check */
return auth_check_serv_cond(ablock);
}



/*************************************************
*              Client entry point                *
*************************************************/

/* For interface, see auths/README */

int
auth_cram_md5_client(
  auth_instance *ablock,                 /* authenticator block */
  void * sx,				 /* smtp connextion */
  int timeout,                           /* command timeout */
  uschar *buffer,                        /* for reading response */
  int buffsize)                          /* size of buffer */
{
auth_cram_md5_options_block *ob =
  (auth_cram_md5_options_block *)(ablock->options_block);
uschar *secret = expand_string(ob->client_secret);
uschar *name = expand_string(ob->client_name);
uschar *challenge, *p;
int i;
uschar digest[16];

/* If expansion of either the secret or the user name failed, return CANCELLED
or ERROR, as appropriate. */

if (!secret || !name)
  {
  if (f.expand_string_forcedfail)
    {
    *buffer = 0;           /* No message */
    return CANCELLED;
    }
  string_format(buffer, buffsize, "expansion of \"%s\" failed in "
    "%s authenticator: %s",
    !secret ? ob->client_secret : ob->client_name,
    ablock->name, expand_string_message);
  return ERROR;
  }

/* Initiate the authentication exchange and read the challenge, which arrives
in base 64. */

if (smtp_write_command(sx, SCMD_FLUSH, "AUTH %s\r\n", ablock->public_name) < 0)
  return FAIL_SEND;
if (!smtp_read_response(sx, buffer, buffsize, '3', timeout))
  return FAIL;

if (b64decode(buffer + 4, &challenge) < 0)
  {
  string_format(buffer, buffsize, "bad base 64 string in challenge: %s",
    big_buffer + 4);
  return ERROR;
  }

/* Run the CRAM-MD5 algorithm on the secret and the challenge */

compute_cram_md5(secret, challenge, digest);

/* Create the response from the user name plus the CRAM-MD5 digest */

string_format(big_buffer, big_buffer_size - 36, "%s", name);
for (p = big_buffer; *p; ) p++;
*p++ = ' ';

for (i = 0; i < 16; i++)
  p += sprintf(CS p, "%02x", digest[i]);

/* Send the response, in base 64, and check the result. The response is
in big_buffer, but b64encode() returns its result in working store,
so calling smtp_write_command(), which uses big_buffer, is OK. */

buffer[0] = 0;
if (smtp_write_command(sx, SCMD_FLUSH, "%s\r\n", b64encode(big_buffer,
  p - big_buffer)) < 0) return FAIL_SEND;

return smtp_read_response(sx, US buffer, buffsize, '2', timeout)
  ? OK : FAIL;
}
#endif  /* STAND_ALONE */


/*************************************************
**************************************************
*             Stand-alone test program           *
**************************************************
*************************************************/

#ifdef STAND_ALONE

int main(int argc, char **argv)
{
int i;
uschar *secret = US argv[1];
uschar *challenge = US argv[2];
uschar digest[16];

compute_cram_md5(secret, challenge, digest);

for (i = 0; i < 16; i++) printf("%02x", digest[i]);
printf("\n");

return 0;
}

#endif

#endif	/*!MACRO_PREDEF*/
/* End of cram_md5.c */
