#ifndef HASH_HMAC_H
#define HASH_HMAC_H

#include "common/bytes/span/span.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "crypto/symmetric/hash/hash/sha384.h"

/**
 * @file
 * FIPS 198-1 HMAC-SHA-256, HMAC-SHA-384 and HMAC-SHA-512. Outputs are
 * 32-byte, 48-byte and 64-byte MACs respectively.
 */

/**
 * Compute HMAC-SHA-256(key, msg).
 *
 * @param key MAC key (any length; keys longer than one block are hashed)
 * @param msg message to authenticate
 * @param out receives the 32-byte MAC
 */
void hmac_sha256(wired_span key, wired_span msg, u8 out[SHA256_DIGEST]);

/**
 * Compute HMAC-SHA-256(key, msg) truncated to its leftmost out_len bytes
 * (FIPS 198-1 5, "Truncation of HMAC Output": MAC = leftmost Tlen bytes of
 * HMAC(K, text)).
 *
 * @param key     MAC key (any length; keys longer than one block are hashed)
 * @param msg     message to authenticate
 * @param out     receives the truncated MAC
 * @param out_len number of leftmost bytes to keep (0..SHA256_DIGEST)
 */
void hmac_sha256_truncated(
    wired_span key, wired_span msg, u8* out, usz out_len);

/**
 * Compute HMAC-SHA-384(key, msg) (RFC 2104, FIPS 180-4 SHA-384).
 *
 * @param key MAC key (any length; keys longer than one block are hashed)
 * @param msg message to authenticate
 * @param out receives the 48-byte MAC
 */
void hmac_sha384(wired_span key, wired_span msg, u8 out[SHA384_DIGEST]);

/**
 * Compute HMAC-SHA-512(key, msg) (RFC 2104, FIPS 180-4 SHA-512).
 *
 * @param key MAC key (any length; keys longer than one block are hashed)
 * @param msg message to authenticate
 * @param out receives the 64-byte MAC
 */
void hmac_sha512(wired_span key, wired_span msg, u8 out[SHA512_DIGEST]);

#endif
