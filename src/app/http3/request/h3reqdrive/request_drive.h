#ifndef WIRED_H3REQDRIVE_REQUEST_DRIVE_H
#define WIRED_H3REQDRIVE_REQUEST_DRIVE_H

#include "app/http3/core/h3/priority.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * RFC 9114 4.1 / 4.3.1, RFC 9204 4.5: drive HTTP/3 requests end to end:
 * QPACK-encode and frame outgoing GET or arbitrary-method requests, and
 * recover the pseudo-headers of received ones. */

/** The :path and :authority values for a GET request. */
typedef struct {
  quic_span path;      /**< the :path pseudo-header value */
  quic_span authority; /**< the :authority pseudo-header value */
} wired_h3reqdrive_get_in;

/** RFC 9114 4.1 / 4.3.1, RFC 9204 4.5: drive an HTTP/3 GET request end to
 * end: QPACK-encode the request pseudo-headers (h3reqenc), wrap them in a
 * HEADERS frame and a QUIC STREAM frame (h3conn).
 * @param stream_id the request stream id to write in the STREAM frame
 * @param in the :path and :authority values
 * @param out receives the encoded STREAM frame
 * @return 1 with out->len set, 0 on overflow. */
int wired_h3reqdrive_send_get(
    u64 stream_id, const wired_h3reqdrive_get_in* in, quic_obuf* out);

/** Remaining arguments of wired_h3reqdrive_send_method beyond stream_id/out:
 * the request line (method/path/authority) and the optional body. */
typedef struct {
  quic_span method;    /**< the :method pseudo-header value */
  quic_span path;      /**< the :path pseudo-header value */
  quic_span authority; /**< the :authority pseudo-header value */
  quic_span body;      /**< optional request body; empty for none */
} wired_h3reqdrive_send_in;

/** RFC 9114 4.1 / 4.3.1, RFC 9204 4.5: drive an arbitrary-method HTTP/3
 * request end to end: QPACK-encode the request pseudo-headers with the given
 * :method, append a DATA frame when in->body is non-empty, and wrap in a
 * STREAM frame.
 * @param stream_id the request stream id to write in the STREAM frame
 * @param in the request line (method/path/authority) and the optional body
 * @param out receives the encoded STREAM frame
 * @return 1 with out->len set, 0 on overflow. */
int wired_h3reqdrive_send_method(
    u64 stream_id, const wired_h3reqdrive_send_in* in, quic_obuf* out);

/** RFC 9114 4.1 / 4.3.1, RFC 9204 4.5: recovered request pseudo-headers.
 * Each value is either a static-table view or a copy in the caller-supplied
 * scratch buffer, depending on how the peer encoded the field line. */
typedef struct {
  const u8* method;     /**< :method value (static-table view or scratch) */
  usz       method_len; /**< method length in octets */
  const u8* scheme;     /**< :scheme value (static-table view or scratch) */
  usz       scheme_len; /**< scheme length in octets */
  const u8* authority;  /**< :authority value (static-table view or
                           scratch) */
  usz              authority_len; /**< authority length in octets */
  const u8*        path;     /**< :path value (static-table view or scratch) */
  usz              path_len; /**< path length in octets */
  const u8*        protocol; /**< RFC 9220 3: :protocol value, 0 if absent */
  usz              protocol_len; /**< protocol length in octets, 0 if absent */
  const u8*        body; /**< request body view into stream_data, 0 if none */
  usz              body_len; /**< 0 for GET and other bodyless requests */
  quic_h3_priority priority; /**< RFC 9218 5 priority header (defaults) */
  const u8* origin; /**< regular `origin` header value (static-table view or
                       scratch), 0 if absent (RFC 9220 3 / WebTransport draft
                       SS3.6 origin check applies only when present) */
  usz origin_len;   /**< origin length in octets, 0 if absent */
  /** WebTransport subprotocol negotiation: the raw `wt-available-protocols`
   * header value (an RFC 8941 sf-list of sf-strings, the client's offer in
   * preference order), copied verbatim -- not a scratch view like origin,
   * so the offer survives past the decode's scratch lifetime. A value that
   * does not fit is dropped (treated as absent). */
  u8  wt_avail[256];
  usz wt_avail_len; /**< wt-available-protocols length in octets, 0 if absent */
} wired_h3reqdrive_req;

/** RFC 9114 4.1, RFC 9204 4.5: decode a STREAM frame carrying a request:
 * recover :method, :scheme, :authority and :path from the leading HEADERS
 * frame's QPACK field section. Literal values are copied into scratch.
 * A trailing DATA frame (POST/PUT/PATCH body) is viewed in place via
 * r->body / r->body_len; bodyless requests leave body_len 0.
 * @param stream_data the STREAM frame payload carrying the request
 * @param scratch caller-supplied buffer backing r's literal values; the
 *   caller keeps it alive while r is in use
 * @param r receives the recovered pseudo-headers and body view
 * @return 1 on success, 0 on a malformed frame or field section. */
int wired_h3reqdrive_recv_get(
    quic_span stream_data, quic_mspan scratch, wired_h3reqdrive_req* r);

#endif
