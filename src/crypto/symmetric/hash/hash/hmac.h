#ifndef QUIC_HASH_HMAC_H
#define QUIC_HASH_HMAC_H

#include "common/bytes/span/span.h"
#include "crypto/symmetric/hash/hash/sha256.h"

/**
 * @file
 * FIPS 198-1 HMAC-SHA-256. Output is a 32-byte MAC.
 */

/**
 * Compute HMAC-SHA-256(key, msg).
 *
 * @param key MAC key (any length; keys longer than one block are hashed)
 * @param msg message to authenticate
 * @param out receives the 32-byte MAC
 */
void quic_hmac_sha256(quic_span key, quic_span msg, u8 out[QUIC_SHA256_DIGEST]);

#endif
