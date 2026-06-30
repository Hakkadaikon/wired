#ifndef QUIC_HASH_HMAC_H
#define QUIC_HASH_HMAC_H

#include "crypto/symmetric/hash/hash/sha256.h"

/* FIPS 198-1 HMAC-SHA-256. Output is a 32-byte MAC. */

void quic_hmac_sha256(
    const u8 *key,
    usz       key_len,
    const u8 *msg,
    usz       msg_len,
    u8        out[QUIC_SHA256_DIGEST]);

#endif
