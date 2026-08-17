#ifndef HASH_SHA512_H
#define HASH_SHA512_H

#include "common/platform/sys/syscall.h"

/* FIPS 180-4 SHA-512. Produces a 64-byte digest. */

#define SHA512_DIGEST 64
#define SHA512_BLOCK 128

/** Incremental SHA-512 state: running hash, total bytes absorbed, and the
 * partial-block buffer. */
typedef struct {
  u64 h[8];              /**< running hash state */
  u64 total;             /**< total bytes absorbed (low 64 bits suffice here) */
  u8  buf[SHA512_BLOCK]; /**< partial-block buffer */
  usz buf_len;           /**< bytes pending in buf */
} sha512_ctx;

void sha512_init(sha512_ctx* s);
void sha512_update(sha512_ctx* s, const u8* data, usz len);
void sha512_final(sha512_ctx* s, u8 out[SHA512_DIGEST]);

/* One-shot convenience: digest of data[0..len). */
void sha512(const u8* data, usz len, u8 out[SHA512_DIGEST]);

#endif
