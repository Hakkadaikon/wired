#ifndef QUIC_QPACK_PREFIX_H
#define QUIC_QPACK_PREFIX_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 4.5.1. The Encoded Field Section Prefix: an 8-bit-prefix Required
 * Insert Count followed by a Sign bit (S) and a 7-bit-prefix Delta Base.
 *
 * Required Insert Count is transmitted in the encoded form of 4.5.1.1; with an
 * empty dynamic table it is 0 and the wire value is 0. Delta Base together with
 * the Sign bit yields the Base relative to Required Insert Count. */
typedef struct {
  u64 required_insert_count; /* wire-encoded value (0 when table is empty) */
  u8  sign;                  /* S bit: 0 Base >= ReqInsertCount, 1 below */
  u64 delta_base;
} quic_qpack_prefix;

/* Encode the prefix into buf of cap bytes. Returns bytes written or 0. */
usz quic_qpack_prefix_encode(u8 *buf, usz cap, const quic_qpack_prefix *p);

/* Decode the prefix from buf of n bytes. Returns bytes consumed or 0. */
usz quic_qpack_prefix_decode(const u8 *buf, usz n, quic_qpack_prefix *p);

#endif
