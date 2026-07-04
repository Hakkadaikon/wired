#ifndef QUIC_H3CONN_RESPONSE_H
#define QUIC_H3CONN_RESPONSE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. An HTTP/3 response: the :status, its DATA body (viewed in
 * place, body.n == 0 when absent), and an optional content-type (0 to omit
 * the field line). Doubles as the encode input and the decode output; decode
 * never populates content_type (left 0). content_type is appended last so
 * existing {status, body} initializers still compile (it defaults to 0). */
typedef struct {
  u16         status;
  quic_span   body;
  const char* content_type;
} quic_h3conn_resp;

/* RFC 9114 4.1. Build an HTTP/3 response (a HEADERS frame carrying the
 * QPACK-encoded :status, plus a DATA frame when body is non-empty) and wrap
 * it in a QUIC STREAM frame (RFC 9000 19.8) for stream_id at offset 0 with
 * the FIN bit set. Returns 1 with out->len set, 0 if out lacks capacity. */
int quic_h3conn_send_response(
    u64 stream_id, const quic_h3conn_resp* resp, quic_obuf* out);

/* RFC 9114 4.1. Decode a STREAM frame (RFC 9000 19.8) carrying an HTTP/3
 * response: recover the :status from the leading HEADERS frame and view the
 * DATA body in place. Returns 1 on success, 0 on a malformed frame or
 * unrecognised :status encoding. */
int quic_h3conn_recv_response(quic_span stream_data, quic_h3conn_resp* resp);

#endif
