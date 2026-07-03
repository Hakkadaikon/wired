#ifndef QUIC_HASH_SHA256_H
#define QUIC_HASH_SHA256_H

#include "common/platform/sys/syscall.h"

/**
 * @file
 * FIPS 180-4 SHA-256. Produces a 32-byte digest.
 */

#define QUIC_SHA256_DIGEST 32 /**< digest length in bytes */
#define QUIC_SHA256_BLOCK 64  /**< internal block length in bytes */

/**
 * Streaming SHA-256 state. Initialize with quic_sha256_init(), feed with
 * quic_sha256_update(), finish with quic_sha256_final().
 */
typedef struct {
  u32 h[8];                   /**< running hash state */
  u64 total;                  /**< total bytes absorbed */
  u8  buf[QUIC_SHA256_BLOCK]; /**< partial-block staging buffer */
  usz buf_len;                /**< bytes pending in buf */
} quic_sha256_ctx;

/**
 * Reset s to the initial SHA-256 state.
 *
 * @param s context to initialize
 */
void quic_sha256_init(quic_sha256_ctx *s);

/**
 * Absorb data[0..len) into the running hash.
 *
 * @param s    context previously initialized
 * @param data bytes to absorb
 * @param len  number of bytes at data
 */
void quic_sha256_update(quic_sha256_ctx *s, const u8 *data, usz len);

/**
 * Finish the hash and write the digest.
 *
 * @param s   context to finalize (its state is consumed)
 * @param out receives the 32-byte digest
 */
void quic_sha256_final(quic_sha256_ctx *s, u8 out[QUIC_SHA256_DIGEST]);

/**
 * One-shot convenience: digest of data[0..len).
 *
 * @param data bytes to hash
 * @param len  number of bytes at data
 * @param out  receives the 32-byte digest
 */
void quic_sha256(const u8 *data, usz len, u8 out[QUIC_SHA256_DIGEST]);

#endif
