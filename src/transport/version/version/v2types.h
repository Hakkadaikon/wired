#ifndef QUIC_VERSION_V2TYPES_H
#define QUIC_VERSION_V2TYPES_H

#include "common/platform/sys/syscall.h"

/* RFC 9369 3.2: QUIC v2 encodes the long header packet types with different
 * wire values than v1. This maps between the version-independent logical type
 * and the per-version 2-bit field (bits 5-4 of byte 0). */

typedef enum {
    QUIC_LT_INITIAL = 0,
    QUIC_LT_0RTT,
    QUIC_LT_HANDSHAKE,
    QUIC_LT_RETRY,
    QUIC_LT_INVALID = -1
} quic_logical_type;

/* Wire value of a logical type under v1 (RFC 9000 17.2) or v2 (RFC 9369 3.2).
 * Returns -1 for an unknown logical type. */
int quic_v1_packet_type(quic_logical_type lt);
int quic_v2_packet_type(quic_logical_type lt);

/* Inverse: the logical type for a 2-bit wire value under v1 / v2.
 * Returns QUIC_LT_INVALID for an out-of-range value. */
quic_logical_type quic_v1_logical_type(int wire);
quic_logical_type quic_v2_logical_type(int wire);

#endif
