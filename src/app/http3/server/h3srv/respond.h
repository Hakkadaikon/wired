#ifndef QUIC_H3SRV_RESPOND_H
#define QUIC_H3SRV_RESPOND_H

#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/state.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. Decode a request HEADERS frame (a STREAM frame carrying a GET)
 * into *req and record that a request has been seen on this connection. Returns
 * 1 on success, 0 on a malformed frame or field section. */
int quic_h3srv_on_request(
    quic_h3srv_state    *st,
    const u8            *stream_data,
    usz                  len,
    u8                  *scratch,
    usz                  scap,
    quic_h3reqdrive_req *req);

/* RFC 9114 4.1 / 4.3.2. Build a response (HEADERS with :status, plus DATA when
 * body_len > 0) on stream_id. Precondition: the server has emitted its own
 * SETTINGS first AND a request has been seen; otherwise returns 0 and writes
 * nothing. Returns 1 with *len set, 0 on a precondition failure or overflow. */
int quic_h3srv_build_response(
    const quic_h3srv_state *st,
    u64                     stream_id,
    u16                     status,
    const u8               *body,
    usz                     body_len,
    u8                     *out,
    usz                     cap,
    usz                    *len);

/* RFC 9110 9.3.2. Build a response for a request whose method is
 * method[0..m_len), suppressing the response body (no DATA frame) when the
 * method is HEAD: a HEAD response carries the same :status and header fields as
 * the GET would but MUST NOT include message content. All other methods behave
 * as quic_h3srv_build_response. Returns 1 with *len set, 0 on a precondition
 * failure or overflow. */
int quic_h3srv_build_response_for_method(
    const quic_h3srv_state *st,
    u64                     stream_id,
    const u8               *method,
    usz                     m_len,
    u16                     status,
    const u8               *body,
    usz                     body_len,
    u8                     *out,
    usz                     cap,
    usz                    *len);

#endif
