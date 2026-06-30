#ifndef QUIC_NET_CHECKSUM_H
#define QUIC_NET_CHECKSUM_H

#include "common/platform/sys/syscall.h"

/* Internet checksum (RFC 1071): the 16-bit one's-complement of the
 * one's-complement sum of the data as 16-bit big-endian words. Used by both
 * the IPv4 header checksum (RFC 791) and the UDP checksum (RFC 768). */

/* Accumulate len bytes into a running 32-bit sum (caller folds at the end). */
u32 quic_cksum_accum(u32 sum, const u8 *data, usz len);

/* Fold carries and take the one's complement to produce the 16-bit field. */
u16 quic_cksum_fold(u32 sum);

/* Convenience: full checksum over one buffer. */
u16 quic_cksum(const u8 *data, usz len);

#endif
