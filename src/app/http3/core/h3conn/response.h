#ifndef QUIC_H3CONN_RESPONSE_H
#define QUIC_H3CONN_RESPONSE_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. Build an HTTP/3 response (a HEADERS frame carrying the
 * QPACK-encoded :status, plus a DATA frame when body_len > 0) and wrap it in a
 * QUIC STREAM frame (RFC 9000 19.8) for stream_id at offset 0 with the FIN bit
 * set. Returns 1 with *out_len set, 0 if out lacks capacity. */
int quic_h3conn_send_response(
    u64       stream_id,
    u16       status,
    const u8 *body,
    usz       body_len,
    u8       *out,
    usz       cap,
    usz      *out_len);

/* RFC 9114 4.1. Decode a STREAM frame (RFC 9000 19.8) carrying an HTTP/3
 * response: recover the :status from the leading HEADERS frame and view the
 * DATA body in place (*body is 0 and *body_len 0 when no body). Returns 1 on
 * success, 0 on a malformed frame or unrecognised :status encoding. */
int quic_h3conn_recv_response(
    const u8  *stream_data,
    usz        len,
    u16       *status,
    const u8 **body,
    usz       *body_len);

#endif
