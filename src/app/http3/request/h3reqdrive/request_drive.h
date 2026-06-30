#ifndef QUIC_H3REQDRIVE_REQUEST_DRIVE_H
#define QUIC_H3REQDRIVE_REQUEST_DRIVE_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5. Drive an HTTP/3 GET request end to end:
 * QPACK-encode the request pseudo-headers (h3reqenc), wrap them in a HEADERS
 * frame and a QUIC STREAM frame (h3conn). Returns 1 with *out_len set, 0 on
 * overflow. */
int quic_h3reqdrive_send_get(
    u64       stream_id,
    const u8 *path,
    usz       p_len,
    const u8 *authority,
    usz       a_len,
    u8       *out,
    usz       cap,
    usz      *out_len);

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5. Drive an arbitrary-method HTTP/3 request
 * end to end: QPACK-encode the request pseudo-headers with the given :method,
 * append a DATA frame when body_len > 0, and wrap in a STREAM frame. Returns 1
 * with *out_len set, 0 on overflow. */
int quic_h3reqdrive_send_method(
    u64       stream_id,
    const u8 *method,
    usz       m_len,
    const u8 *path,
    usz       p_len,
    const u8 *authority,
    usz       a_len,
    const u8 *body,
    usz       body_len,
    u8       *out,
    usz       cap,
    usz      *out_len);

/* RFC 9114 4.1 / 4.3.1, RFC 9204 4.5. Recovered request pseudo-headers. The
 * authority and path point into a caller-supplied scratch buffer; method and
 * scheme are borrowed from the static table. */
typedef struct {
  const u8 *method;
  usz       method_len;
  const u8 *scheme;
  usz       scheme_len;
  const u8 *authority;
  usz       authority_len;
  const u8 *path;
  usz       path_len;
  const u8 *body;     /* request body view into stream_data, 0 if none */
  usz       body_len; /* 0 for GET and other bodyless requests */
} quic_h3reqdrive_req;

/* RFC 9114 4.1, RFC 9204 4.5. Decode a STREAM frame carrying a request:
 * recover :method, :scheme, :authority and :path from the leading HEADERS
 * frame's QPACK field section. Literal values are copied into scratch (scap
 * octets). A trailing DATA frame (POST/PUT/PATCH body) is viewed in place via
 * r->body / r->body_len; bodyless requests leave body_len 0. Returns 1 on
 * success, 0 on a malformed frame or field section. */
int quic_h3reqdrive_recv_get(
    const u8            *stream_data,
    usz                  len,
    u8                  *scratch,
    usz                  scap,
    quic_h3reqdrive_req *r);

#endif
