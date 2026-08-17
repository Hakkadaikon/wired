#ifndef QUIC_VERSION_V2TYPES_H
#define QUIC_VERSION_V2TYPES_H

#include "common/platform/sys/syscall.h"

/* RFC 9369 3.2: QUIC v2 encodes the long header packet types with different
 * wire values than v1. This maps between the version-independent logical type
 * and the per-version 2-bit field (bits 5-4 of byte 0). */

typedef enum {
  QUIC_LT_INITIAL   = 0,
  QUIC_LT_0RTT      = 1,
  QUIC_LT_HANDSHAKE = 2,
  QUIC_LT_RETRY     = 3,
  QUIC_LT_INVALID   = -1
} logical_type;

/* Wire value of a logical type under v1 (RFC 9000 17.2) or v2 (RFC 9369 3.2).
 * Returns -1 for an unknown logical type. */
int v1_packet_type(logical_type lt);
int v2_packet_type(logical_type lt);

/* Inverse: the logical type for a 2-bit wire value under v1 / v2.
 * Returns QUIC_LT_INVALID for an out-of-range value. */
logical_type v1_logical_type(int wire);
logical_type v2_logical_type(int wire);

#endif
