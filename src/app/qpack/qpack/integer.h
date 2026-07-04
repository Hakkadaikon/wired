#ifndef QUIC_QPACK_INTEGER_H
#define QUIC_QPACK_INTEGER_H

#include "common/bytes/span/span.h"

/* RFC 9204 4.1.1 / RFC 7541 5.1. Prefixed variable-length integer. The first
 * byte holds prefix_bits low bits of the value (the pattern occupies the high
 * bits above them). Values below 2^prefix_bits - 1 fit in the prefix; larger
 * values set every prefix bit and continue in 7-bit groups with a continuation
 * bit in the MSB of each trailing byte. */

/* The first byte's layout: the prefix length and the fixed high bits (e.g. a
 * representation pattern) ORed above it. */
typedef struct {
  u8 bits;    /* prefix length in bits */
  u8 pattern; /* fixed high bits above the prefix */
} quic_qpack_pfx;

/* Encode value under pfx into buf. Returns bytes written, or 0 if it does not
 * fit. */
usz quic_qpack_int_encode(quic_mspan buf, quic_qpack_pfx pfx, u64 value);

/* Decode an N-bit prefixed integer from buf into *value.
 * Returns bytes consumed, or 0 on truncation / overflow. */
usz quic_qpack_int_decode(quic_span buf, u8 prefix_bits, u64* value);

#endif
