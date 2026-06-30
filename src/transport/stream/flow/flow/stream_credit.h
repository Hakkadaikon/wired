#ifndef QUIC_FLOW_STREAM_CREDIT_H
#define QUIC_FLOW_STREAM_CREDIT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.6: an endpoint limits how many streams its peer may open via
 * MAX_STREAMS. This tracks the grant locally: each open consumes one slot up
 * to max_streams, and a grant raises the limit (it never lowers it). */

typedef struct {
    u64 max_streams; /* maximum streams the peer may open */
    u64 count;       /* how many have been opened so far */
} quic_stream_credit;

void quic_stream_credit_init(quic_stream_credit *s, u64 max_streams);

/* Open one stream. Returns 1 and increments the count if under the limit, 0 if
 * the limit is reached (a STREAM_LIMIT_ERROR; the count is left unchanged). */
int quic_stream_credit_open(quic_stream_credit *s);

/* Raise the limit from a MAX_STREAMS frame. A value not larger than the
 * current limit is ignored (the limit never decreases). */
void quic_stream_credit_grant(quic_stream_credit *s, u64 new_max);

#endif
