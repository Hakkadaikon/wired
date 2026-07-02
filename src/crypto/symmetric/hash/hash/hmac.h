#ifndef QUIC_HASH_HMAC_H
#define QUIC_HASH_HMAC_H

#include "common/bytes/span/span.h"
#include "crypto/symmetric/hash/hash/sha256.h"

/* FIPS 198-1 HMAC-SHA-256. Output is a 32-byte MAC. */

void quic_hmac_sha256(quic_span key, quic_span msg, u8 out[QUIC_SHA256_DIGEST]);

#endif
