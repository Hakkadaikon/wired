#ifndef WIRED_H3SRV_RESPOND_H
#define WIRED_H3SRV_RESPOND_H

#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/state.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* The request STREAM frame bytes to decode and the caller's decode scratch
 * buffer (view-only fields of the decoded request borrow into it). */
typedef struct {
  quic_span  stream_data;
  quic_mspan scratch;
} wired_h3srv_req_in;

/* RFC 9114 4.1. Decode a request HEADERS frame (a STREAM frame carrying a GET)
 * into *req and record that a request has been seen on this connection.
 * Returns 1 on success, 0 on a malformed frame or field section. */
int wired_h3srv_on_request(
    wired_h3srv_state        *st,
    const wired_h3srv_req_in *in,
    wired_h3reqdrive_req     *req);

/* The request stream to reply on and the response to build. */
typedef struct {
  u64              stream_id;
  quic_h3conn_resp resp;
} wired_h3srv_send_in;

/* RFC 9114 4.1 / 4.3.2. Build a response (HEADERS with :status, plus DATA when
 * body is non-empty) on in->stream_id. Precondition: the server has emitted
 * its own SETTINGS first AND a request has been seen; otherwise returns 0 and
 * writes nothing. Returns 1 with out->len set, 0 on a precondition failure or
 * overflow. */
int wired_h3srv_build_response(
    const wired_h3srv_state *st, const wired_h3srv_send_in *in, quic_obuf *out);

/* The request method (used only to detect HEAD) and the response to send. */
typedef struct {
  quic_span           method;
  wired_h3srv_send_in send;
} wired_h3srv_resp_for_method_in;

/* RFC 9110 9.3.2. Build a response for a request whose method is in->method,
 * suppressing the response body (no DATA frame) when the method is HEAD: a
 * HEAD response carries the same :status and header fields as the GET would
 * but MUST NOT include message content. All other methods behave as
 * wired_h3srv_build_response. Returns 1 with out->len set, 0 on a precondition
 * failure or overflow. */
int wired_h3srv_build_response_for_method(
    const wired_h3srv_state              *st,
    const wired_h3srv_resp_for_method_in *in,
    quic_obuf                            *out);

#endif
