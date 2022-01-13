/* -----------------------------------------------------------------------
 * 
 * umac.h -- C Implementation UMAC Message Authentication
 *
 * Version 0.93a of rfc4418.txt -- 2006 July 14
 *
 * For a full description of UMAC message authentication see the UMAC
 * world-wide-web page at http://www.cs.ucdavis.edu/~rogaway/umac
 * Please report bugs and suggestions to the UMAC webpage.
 *
 * Copyright (c) 1999-2004 Ted Krovetz
 *                                                                 
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and with or without fee, is hereby
 * granted provided that the above copyright notice appears in all copies
 * and in supporting documentation, and that the name of the copyright
 * holder not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior permission.
 *
 * Comments should be directed to Ted Krovetz (tdk@acm.org)
 *                                                                   
 * ---------------------------------------------------------------------- */
 
 /* ////////////////////// IMPORTANT NOTES /////////////////////////////////
  *
  * 1) This version does not work properly on messages larger than 16MB
  *
  * 2) If you set the switch to use SSE2, then all data must be 16-byte
  *    aligned
  *
  * 3) When calling the function umac(), it is assumed that msg is in
  * a writable buffer of length divisible by 32 bytes. The message itself
  * does not have to fill the entire buffer, but bytes beyond msg may be
  * zeroed.
  *
  * 4) Two free AES implementations are supported by this implementation of
  * UMAC. Paulo Barreto's version is in the public domain and can be found
  * at http://www.esat.kuleuven.ac.be/~rijmen/rijndael/ (search for
  * "Barreto"). The only two files needed are rijndael-alg-fst.c and
  * rijndael-alg-fst.h.
  * Brian Gladman's version is distributed with GNU Public License
  * and can be found at http://fp.gladman.plus.com/AES/index.htm. It
  * includes a fast IA-32 assembly version.
  *
  /////////////////////////////////////////////////////////////////////// */
#ifndef HEADER_UMAC_H
#define HEADER_UMAC_H

#ifdef __cplusplus
    extern "C" {
#endif

struct umac_ctx *umac_alloc(void);
/* Dynamically allocate a umac_ctx struct. */

struct umac_ctx *umac_new(unsigned char key[]);
/* Dynamically allocate a umac_ctx struct, initialize variables, 
 * generate subkeys from key.
 */

void umac_init(struct umac_ctx *ctx, unsigned char key[]);
/* Initialize a previously allocated umac_ctx struct. */

int umac_reset(struct umac_ctx *ctx);
/* Reset a umac_ctx to begin authenticating a new message */

int umac_update(struct umac_ctx *ctx, unsigned char *input, long len);
/* Incorporate len bytes pointed to by input into context ctx */

int umac_final(struct umac_ctx *ctx, unsigned char tag[], unsigned char nonce[8]);
/* Incorporate any pending data and the ctr value, and return tag. 
 * This function returns error code if ctr < 0. 
 */

int umac_delete(struct umac_ctx *ctx);
/* Deallocate the context structure */

/* ProFTPD Note: We reuse umac_ctx for the umac-128 implementation, as the
 * structure is opaque.  We simply recompile the umac.c file with different
 * preprocessor macros to get the umac-128 implementation.
 */
struct umac_ctx *umac128_alloc(void);
struct umac_ctx *umac128_new(unsigned char key[]);
void umac128_init(struct umac_ctx *ctx, unsigned char key[]);
int umac128_reset(struct umac_ctx *ctx);
int umac128_update(struct umac_ctx *ctx, unsigned char *input, long len);
int umac128_final(struct umac_ctx *ctx, unsigned char tag[], unsigned char nonce[8]);
int umac128_delete(struct umac_ctx *ctx);

#ifdef __cplusplus
    }
#endif

#endif /* HEADER_UMAC_H */
