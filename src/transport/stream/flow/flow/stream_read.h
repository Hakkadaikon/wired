#ifndef QUIC_FLOW_STREAM_READ_H
#define QUIC_FLOW_STREAM_READ_H

#include "common/platform/sys/syscall.h"
#include "transport/stream/flow/flow/reassemble.h"

/* RFC 9000 2.2: deliver received STREAM data to the application as an ordered
 * byte stream. Out-of-order bytes are buffered; only the contiguous prefix
 * from the current read position is handed up, stopping at the first gap. */

typedef struct {
  quic_reasm r;
  u64        read_off; /* bytes already pulled by the application */
} quic_stream_read;

void quic_stream_read_init(quic_stream_read *s);

/* Buffer len bytes received at the given stream offset. Returns 1 on success,
 * 0 if it exceeds capacity or a known final size. */
int quic_stream_read_push(
    quic_stream_read *s, u64 offset, const u8 *data, usz len);

/* Copy up to cap contiguous bytes from the read position into out, advancing
 * past them. Stops at the first gap. Sets *out_len to the count copied. */
void quic_stream_read_pull(quic_stream_read *s, u8 *out, usz cap, usz *out_len);

#endif
