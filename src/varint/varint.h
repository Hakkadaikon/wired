#ifndef QUIC_VARINT_H
#define QUIC_VARINT_H

#include "sys/syscall.h"

/* RFC 9000 16. Variable-length integer encoding.
 * 2-bit prefix in MSB of first byte selects length 1/2/4/8. */

#define QUIC_VARINT_MAX 0x3FFFFFFFFFFFFFFFULL

/* Bytes needed to encode v. Returns 0 if v exceeds the 62-bit range. */
usz quic_varint_len(u64 v);

/* Encode v into buf (must hold quic_varint_len(v) bytes).
 * Returns bytes written, or 0 if v out of range. */
usz quic_varint_encode(u8 *buf, u64 v);

/* Decode from buf of n readable bytes into *out.
 * Returns bytes consumed, or 0 if n too small for the encoded length. */
usz quic_varint_decode(const u8 *buf, usz n, u64 *out);

#endif
