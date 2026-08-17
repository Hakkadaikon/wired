#ifndef HASH_SHA384_H
#define HASH_SHA384_H

#include "crypto/symmetric/hash/hash/sha512.h"

/* FIPS 180-4 5.3.4 SHA-384: the SHA-512 compression with its own initial
 * hash value and the digest truncated to 48 bytes. Reuses sha512_ctx
 * and sha512_update. */

#define SHA384_DIGEST 48

void sha384_init(sha512_ctx* s);
void sha384_final(sha512_ctx* s, u8 out[SHA384_DIGEST]);

/* One-shot convenience: digest of data[0..len). */
void sha384(const u8* data, usz len, u8 out[SHA384_DIGEST]);

#endif
