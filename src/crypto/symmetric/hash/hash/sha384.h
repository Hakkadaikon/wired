#ifndef QUIC_HASH_SHA384_H
#define QUIC_HASH_SHA384_H

#include "crypto/symmetric/hash/hash/sha512.h"

/* FIPS 180-4 5.3.4 SHA-384: the SHA-512 compression with its own initial
 * hash value and the digest truncated to 48 bytes. Reuses quic_sha512_ctx
 * and quic_sha512_update. */

#define QUIC_SHA384_DIGEST 48

void quic_sha384_init(quic_sha512_ctx* s);
void quic_sha384_final(quic_sha512_ctx* s, u8 out[QUIC_SHA384_DIGEST]);

/* One-shot convenience: digest of data[0..len). */
void quic_sha384(const u8* data, usz len, u8 out[QUIC_SHA384_DIGEST]);

#endif
