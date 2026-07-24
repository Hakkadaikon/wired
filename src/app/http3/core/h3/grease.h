#ifndef QUIC_H3_GREASE_H
#define QUIC_H3_GREASE_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 reserves values of the form 0x1f * N + 0x21 across frame types
 * (7.2.8), stream types (6.2.3), settings identifiers (7.2.4.1), and error
 * codes (8.1) for grease. A receiver must treat any such value as unknown
 * and ignore it rather than failing, keeping the protocol extensible. */

/* Whether a value is a reserved (grease) point to be ignored. The same
 * 0x1f*N + 0x21 pattern applies to H3 frame/stream/setting/error spaces. */
int quic_h3_is_reserved(u64 value);

/* Compute the Nth reserved (grease) point: 0x1f*n + 0x21. The inverse of
 * quic_h3_is_reserved -- feeding it any n always yields a value it accepts.
 * Shared by every space that sends a grease value on the wire (e.g. a
 * SETTINGS identifier, 9114-064; an error code, 9114-077), each picking its
 * own n (typically from a random byte) and calling this once. */
u64 quic_h3_grease_value(u64 n);

#endif
