#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/frame_permit.h"
#include "app/http3/request/h3req/reqorder.h"
#include "app/http3/request/h3reqdrive/request_parse_impl.h"

static int is_message_frame(u64 t);
static int after_headers_ok(h3req_order_state* s, u64 t);
static int frames_step(
    wired_span h3, usz* off, h3req_order_state* s, wired_h3reqdrive_req* r);

/* RFC 9114 7.2.3-7.2.8 (9114-057/060/067/069/073): 1 if a frame of type t
 * may appear on a request stream at all -- not CANCEL_PUSH, SETTINGS,
 * GOAWAY or MAX_PUSH_ID (control stream only), PUSH_PROMISE (this SDK is
 * server-only) or an HTTP/2-only reserved type. */
int h3reqdrive_frame_type_ok(u64 t) {
  return h3_frame_on_stream(t, H3_STREAM_KIND_REQUEST) && h3_frame_recv_ok(t);
}

/* A frame of the HTTP message itself (RFC 9114 4.1). */
static int is_message_frame(u64 t) {
  return t == H3_FRAME_HEADERS || t == H3_FRAME_DATA;
}

/* RFC 9114 4.1 (9114-005/007): after the leading HEADERS, DATA may repeat
 * and one trailing HEADERS may close the message; nothing of the message
 * follows it. Unknown and reserved types are skipped anywhere (9). */
static int after_headers_ok(h3req_order_state* s, u64 t) {
  if (!h3reqdrive_frame_type_ok(t)) {
    return 0;
  }
  if (!is_message_frame(t)) {
    return 1;
  }
  return h3req_order_accept(s, t);
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
  r->frame_unexpected = !after_headers_ok(s, f.type);
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
