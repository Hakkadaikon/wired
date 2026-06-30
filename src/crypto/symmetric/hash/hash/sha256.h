#ifndef QUIC_HASH_SHA256_H
#define QUIC_HASH_SHA256_H

#include "common/platform/sys/syscall.h"

/* FIPS 180-4 SHA-256. Produces a 32-byte digest. */

#define QUIC_SHA256_DIGEST 32
#define QUIC_SHA256_BLOCK 64

typedef struct {
  u32 h[8];  /* running hash state */
  u64 total; /* total bytes absorbed */
  u8  buf[QUIC_SHA256_BLOCK];
  usz buf_len; /* bytes pending in buf */
} quic_sha256_ctx;

void quic_sha256_init(quic_sha256_ctx *s);
void quic_sha256_update(quic_sha256_ctx *s, const u8 *data, usz len);
void quic_sha256_final(quic_sha256_ctx *s, u8 out[QUIC_SHA256_DIGEST]);

/* One-shot convenience: digest of data[0..len). */
void quic_sha256(const u8 *data, usz len, u8 out[QUIC_SHA256_DIGEST]);

#endif
