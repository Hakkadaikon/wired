#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/frame_permit.h"
#include "app/http3/request/h3req/reqorder.h"
#include "app/http3/request/h3reqdrive/request_parse_impl.h"

static int is_message_frame(u64 t);
static int wt_signal_mid_stream(u64 t, usz off);
static int after_headers_reject(h3req_order_state* s, u64 t);
static int frames_step(
    wired_span h3, usz* off, h3req_order_state* s, wired_h3reqdrive_req* r);

/* draft-ietf-webtrans-http3-15 4.3: WT_STREAM (0x41) is legal as a frame
 * type only as the very first bytes of a request stream (offset 0). */
static int wt_signal_mid_stream(u64 t, usz off) {
  return t == H3_STREAM_WEBTRANSPORT_BIDI && off != 0;
}

/* The H3 error a frame of type t at stream offset off raises on a request
 * stream: 0 none, 1 H3_FRAME_UNEXPECTED (RFC 9114 7.2.3-7.2.8, 9114-057/
 * 060/067/069/073: a control-stream-only type, PUSH_PROMISE -- this SDK is
 * server-only -- or an HTTP/2-only reserved type), 2 H3_FRAME_ERROR (a
 * mid-stream WT_STREAM, WTH3-035). */
int h3reqdrive_frame_reject(u64 t, usz off) {
  if (wt_signal_mid_stream(t, off)) {
    return 2;
  }
  return !(
      h3_frame_on_stream(t, H3_STREAM_KIND_REQUEST) && h3_frame_recv_ok(t));
}

/* A frame of the HTTP message itself (RFC 9114 4.1). */
static int is_message_frame(u64 t) {
  return t == H3_FRAME_HEADERS || t == H3_FRAME_DATA;
}

/* RFC 9114 4.1 (9114-005/007): after the leading HEADERS, DATA may repeat
 * and one trailing HEADERS may close the message; nothing of the message
 * follows it. Unknown and reserved types are skipped anywhere (9). Returns
 * h3reqdrive_frame_reject's code; past HEADERS the offset is never 0. */
static int after_headers_reject(h3req_order_state* s, u64 t) {
  int bad = h3reqdrive_frame_reject(t, 1);
  if (bad || !is_message_frame(t)) {
    return bad;
  }
  return !h3req_order_accept(s, t);
}

/* One frame of the walk past HEADERS: 0 (and *unexpected set) on a frame
 * out of order or not allowed here; a truncated tail ends the walk (the
 * body walk below judges it). */
static int frames_step(
    wired_span h3, usz* off, h3req_order_state* s, wired_h3reqdrive_req* r) {
  h3_frame f    = {0};
  usz      used = h3_frame_get(wired_span_of(h3.p + *off, h3.n - *off), &f);
  if (!used) {
    *off = h3.n;
    return 1;
  }
  r->frame_unexpected = after_headers_reject(s, f.type);
  r->data_len += f.type == H3_FRAME_DATA ? f.payload_len : 0; /* 4.1.2 */
  *off += used;
  return !r->frame_unexpected;
}

/* RFC 9114 4.1: H3_FRAME_UNEXPECTED (a connection error) for any frame
 * sequence past the leading HEADERS a request must not carry; the DATA
 * payload total lands in r->data_len. */
int h3reqdrive_frames_after_headers(
    wired_span h3, usz off, wired_h3reqdrive_req* r) {
  h3req_order_state s = H3REQ_ORDER_HEADERS;
  while (off < h3.n) {
    if (!frames_step(h3, &off, &s, r)) {
      return 0;
    }
  }
  return 1;
}
