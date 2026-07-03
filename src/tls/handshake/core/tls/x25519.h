#ifndef QUIC_TLS_X25519_H
#define QUIC_TLS_X25519_H

#include "common/platform/sys/syscall.h"

/** @file
 * RFC 7748 X25519: scalar multiplication on Curve25519 for ECDHE. */

/** X25519 scalar / u-coordinate length in bytes. */
#define QUIC_X25519_LEN 32

/** out = scalar * point on Curve25519. scalar and point are 32-byte
 * little-endian; out is the 32-byte little-endian u-coordinate.
 * @param out receives the u-coordinate of the product
 * @param scalar the 32-byte little-endian scalar
 * @param point the 32-byte little-endian u-coordinate to multiply
 * @return RFC 7748 6.1: 0 if the result is all-zero (low-order point),
 * 1 otherwise. Callers MUST reject a 0 return (contributory behaviour). */
int quic_x25519(
    u8       out[QUIC_X25519_LEN],
    const u8 scalar[QUIC_X25519_LEN],
    const u8 point[QUIC_X25519_LEN]);

/** out = scalar * base point (9). Produces an X25519 public key.
 * @param out receives the public key
 * @param scalar the 32-byte little-endian scalar
 * @return 1 (a public key is never all-zero); typed int for a uniform API. */
int quic_x25519_base(u8 out[QUIC_X25519_LEN], const u8 scalar[QUIC_X25519_LEN]);

#endif
