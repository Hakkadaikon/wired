#ifndef QUIC_STP_PARSE_TP_H
#define QUIC_STP_PARSE_TP_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 18. Scan the transport parameters tp (len bytes) for param_id.
 * On a match: bytes_out and bytes_len point at the raw value (within tp), and
 * *value_out holds the value decoded as a varint (0 if it is not a single
 * varint). Any out pointer may be NULL. Returns 1 if found, 0 otherwise or on
 * malformed input. */
int quic_stp_parse(const u8 *tp, usz len, u64 param_id,
                   u64 *value_out, const u8 **bytes_out, usz *bytes_len);

#endif
