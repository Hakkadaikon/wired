#ifndef QUIC_HASH_SHA512_H
#define QUIC_HASH_SHA512_H

#include "sys/syscall.h"

/* FIPS 180-4 SHA-512. Produces a 64-byte digest. */

#define QUIC_SHA512_DIGEST 64
#define QUIC_SHA512_BLOCK  128

typedef struct {
    u64 h[8];          /* running hash state */
    u64 total;         /* total bytes absorbed (low 64 bits suffice here) */
    u8 buf[QUIC_SHA512_BLOCK];
    usz buf_len;       /* bytes pending in buf */
} quic_sha512_ctx;

void quic_sha512_init(quic_sha512_ctx *s);
void quic_sha512_update(quic_sha512_ctx *s, const u8 *data, usz len);
void quic_sha512_final(quic_sha512_ctx *s, u8 out[QUIC_SHA512_DIGEST]);

/* One-shot convenience: digest of data[0..len). */
void quic_sha512(const u8 *data, usz len, u8 out[QUIC_SHA512_DIGEST]);

#endif
