#ifndef QUIC_H3CONN_REQUEST_H
#define QUIC_H3CONN_REQUEST_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* The QPACK-encoded field section and optional body of an outbound request.
 */
typedef struct {
  quic_span qpack_headers;
  quic_span body;
} quic_h3conn_req_in;

/* RFC 9114 4.1. Build an HTTP/3 request (a HEADERS frame carrying the
 * QPACK-encoded field section, plus a DATA frame when body is non-empty) and
 * wrap it in a QUIC STREAM frame (RFC 9000 19.8) for stream_id at offset 0
 * with the FIN bit set. Returns 1 with out->len set, 0 if out lacks
 * capacity. */
int quic_h3conn_send_request(
    u64 stream_id, const quic_h3conn_req_in *in, quic_obuf *out);

#endif
