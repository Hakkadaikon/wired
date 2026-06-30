#ifndef QUIC_TLS_X25519_H
#define QUIC_TLS_X25519_H

#include "common/platform/sys/syscall.h"

/* RFC 7748 X25519: scalar multiplication on Curve25519 for ECDHE. */

#define QUIC_X25519_LEN 32

/* out = scalar * point on Curve25519. scalar and point are 32-byte
 * little-endian; out is the 32-byte little-endian u-coordinate. */
void quic_x25519(u8 out[QUIC_X25519_LEN],
                 const u8 scalar[QUIC_X25519_LEN],
                 const u8 point[QUIC_X25519_LEN]);

/* out = scalar * base point (9). Produces an X25519 public key. */
void quic_x25519_base(u8 out[QUIC_X25519_LEN],
                      const u8 scalar[QUIC_X25519_LEN]);

#endif
