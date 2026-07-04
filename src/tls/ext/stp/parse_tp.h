#ifndef QUIC_STP_PARSE_TP_H
#define QUIC_STP_PARSE_TP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* On a match: *bytes points at the raw value (within tp), and *value holds
 * the value decoded as a varint (0 if it is not a single varint). Either
 * pointer may be NULL. */
typedef struct {
  u64*       value;
  quic_span* bytes;
} quic_stp_out;

/* RFC 9000 18. Scan the transport parameters tp for param_id, filling out
 * (any member of which may be NULL). Returns 1 if found, 0 otherwise or on
 * malformed input. */
int quic_stp_parse(quic_span tp, u64 param_id, const quic_stp_out* out);

#endif
