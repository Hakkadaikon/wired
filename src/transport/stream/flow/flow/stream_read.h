#ifndef QUIC_FLOW_STREAM_READ_H
#define QUIC_FLOW_STREAM_READ_H

#include "transport/stream/flow/flow/reassemble.h"

/* RFC 9000 2.2: deliver received STREAM data to the application as an ordered
 * byte stream. Out-of-order bytes are buffered; only the contiguous prefix
 * from the current read position is handed up, stopping at the first gap. */

typedef struct {
  quic_reasm r;
  u64        read_off; /* bytes already pulled by the application */
} quic_stream_read;

void quic_stream_read_init(quic_stream_read* s);

/* Buffer data received at the given stream offset. Returns 1 on success,
 * 0 if it exceeds capacity or a known final size. */
int quic_stream_read_push(quic_stream_read* s, u64 offset, quic_span data);

/* Copy up to out->cap contiguous bytes from the read position into out->p,
 * advancing past them. Stops at the first gap. Sets out->len. */
void quic_stream_read_pull(quic_stream_read* s, quic_obuf* out);

#endif
