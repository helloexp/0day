/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/*
 * This file provides the necessary methods for authenticating with
 * Microsoft's Secure Password Authentication.

 * All the code used here was torn by Marc Prud'hommeaux out of the
 * Samba project (by Andrew Tridgell, Jeremy Allison, and others).
 */

/* December 2004: The spa_base64_to_bits() function has no length checking in
it. I have added a check. PH */

/* It seems that some systems have existing but different definitions of some
of the following types. I received a complaint about "int16" causing
compilation problems. So I (PH) have renamed them all, to be on the safe side.

typedef signed short int16;
typedef unsigned short uint16;
typedef unsigned uint32;
typedef unsigned char  uint8;
*/

typedef signed short int16x;
typedef unsigned short uint16x;
typedef unsigned uint32x;
typedef unsigned char  uint8x;

typedef struct
{
       uint16x         len;
       uint16x         maxlen;
       uint32x         offset;
} SPAStrHeader;

typedef struct
{
       char         ident[8];
       uint32x         msgType;
       SPAStrHeader    uDomain;
       uint32x         flags;
       uint8x         challengeData[8];
       uint8x         reserved[8];
       SPAStrHeader    emptyString;
       uint8x         buffer[1024];
       uint32x         bufIndex;
} SPAAuthChallenge;


typedef struct
{
       char         ident[8];
       uint32x         msgType;
       uint32x         flags;
       SPAStrHeader    user;
       SPAStrHeader    domain;
       uint8x         buffer[1024];
       uint32x         bufIndex;
} SPAAuthRequest;

typedef struct
{
       char         ident[8];
       uint32x         msgType;
       SPAStrHeader    lmResponse;
       SPAStrHeader    ntResponse;
       SPAStrHeader    uDomain;
       SPAStrHeader    uUser;
       SPAStrHeader    uWks;
       SPAStrHeader    sessionKey;
       uint32x         flags;
       uint8x         buffer[1024];
       uint32x         bufIndex;
} SPAAuthResponse;

#define spa_request_length(ptr) (((ptr)->buffer - (uint8x*)(ptr)) + (ptr)->bufIndex)

void spa_bits_to_base64 (unsigned char *, const unsigned char *, int);
int spa_base64_to_bits(char *, int, const char *);
void spa_build_auth_response (SPAAuthChallenge *challenge,
       SPAAuthResponse *response, char *user, char *password);
void spa_build_auth_request (SPAAuthRequest *request, char *user,
       char *domain);
extern void spa_smb_encrypt (unsigned char * passwd, unsigned char * c8,
                             unsigned char * p24);
extern void spa_smb_nt_encrypt (unsigned char * passwd, unsigned char * c8,
                                unsigned char * p24);
extern char *unicodeToString(char *p, size_t len);
extern void spa_build_auth_challenge(SPAAuthRequest *, SPAAuthChallenge *);

