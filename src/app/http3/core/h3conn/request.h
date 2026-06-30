#ifndef QUIC_H3CONN_REQUEST_H
#define QUIC_H3CONN_REQUEST_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. Build an HTTP/3 request (a HEADERS frame carrying the
 * QPACK-encoded field section, plus a DATA frame when body_len > 0) and wrap it
 * in a QUIC STREAM frame (RFC 9000 19.8) for stream_id at offset 0 with the FIN
 * bit set. Returns 1 with *out_len set, 0 if out lacks capacity. */
int quic_h3conn_send_request(
    u64       stream_id,
    const u8 *qpack_headers,
    usz       h_len,
    const u8 *body,
    usz       body_len,
    u8       *out,
    usz       cap,
    usz      *out_len);

#endif
