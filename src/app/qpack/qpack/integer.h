#ifndef QUIC_QPACK_INTEGER_H
#define QUIC_QPACK_INTEGER_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 4.1.1 / RFC 7541 5.1. Prefixed variable-length integer. The first
 * byte holds prefix_bits low bits of the value (prefix_value occupies the high
 * bits above them). Values below 2^prefix_bits - 1 fit in the prefix; larger
 * values set every prefix bit and continue in 7-bit groups with a continuation
 * bit in the MSB of each trailing byte. */

/* Encode value with an N-bit prefix into buf of cap bytes. prefix_value holds
 * the high bits (e.g. a representation pattern) ORed into the first byte's top.
 * Returns bytes written, or 0 if it does not fit. */
usz quic_qpack_int_encode(
    u8 *buf, usz cap, u8 prefix_bits, u8 prefix_value, u64 value);

/* Decode an N-bit prefixed integer from buf of n bytes into *value.
 * Returns bytes consumed, or 0 on truncation / overflow. */
usz quic_qpack_int_decode(const u8 *buf, usz n, u8 prefix_bits, u64 *value);

#endif
