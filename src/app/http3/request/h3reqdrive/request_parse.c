#include "app/http3/request/h3reqdrive/request_parse.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/frame_permit.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9114 7.2.5/7.2.8 (9114-067/9114-073): the frame at off decoded to f is
 * one this endpoint must never accept at all -- PUSH_PROMISE (this SDK is
 * server-only and never sends one) or an HTTP/2-only reserved type. Split out
 * of find_headers's loop so the reject latch (r->frame_unexpected) stays a
 * single extra branch there. */
static int find_headers_frame_ok(const h3_frame* f, wired_h3reqdrive_req* r) {
  if (h3_frame_recv_ok(f->type)) return 1;
  r->frame_unexpected = 1;
  return 0;
}

/* One find_headers step: decode the frame at *off into *f and advance *off
 * past it. Returns 1 to keep walking (a skipped frame this endpoint accepts),
 * 0 to stop -- either HEADERS was reached, the stream ran out, or the frame
 * must be rejected (r->frame_unexpected set by find_headers_frame_ok). */
static int find_headers_step(
    wired_span h3, usz* off, h3_frame* f, wired_h3reqdrive_req* r) {
  usz used = h3_frame_get(wired_span_of(h3.p + *off, h3.n - *off), f);
  if (!used) return 0;
  if (!find_headers_frame_ok(f, r)) return 0;
  *off += used;
  return f->type != H3_FRAME_HEADERS;
}

/* RFC 9114 9 / 7.2.8: walk the request stream's HTTP/3 frames, skipping any
 * unknown/reserved frame (e.g. the GREASE frame curl/quiche send), until the
 * HEADERS frame is found; view its field-section payload in place. Returns 1
 * if a HEADERS frame is reached, 0 if the stream ends, is truncated, or
 * carries a frame type this endpoint must reject (r->frame_unexpected set). */
static int find_headers(
    wired_span h3, wired_span* fs, usz* end, wired_h3reqdrive_req* r) {
  h3_frame f   = {0};
  usz      off = 0;
  while (find_headers_step(h3, &off, &f, r)) {
  }
  if (f.type != H3_FRAME_HEADERS) return 0;
  *fs  = wired_span_of(f.payload, (usz)f.payload_len);
  *end = off;
  return 1;
}

/* Decode the frame at cur->off; on a DATA frame view its body into r and
 * stop. Returns 1 when DATA is found (cur->off advanced past it is
 * irrelevant then), 0 on a truncated/undecodable frame, -1 to keep walking
 * (a skipped frame). */
static int body_step(wired_span h3, usz* off, wired_h3reqdrive_req* r) {
  h3_frame f    = {0};
  usz      used = h3_frame_get(wired_span_of(h3.p + *off, h3.n - *off), &f);
  if (!used) return 0;
  *off += used;
  if (f.type != H3_FRAME_DATA) return -1;
  r->body     = f.payload;
  r->body_len = (usz)f.payload_len;
  return 1;
}

/* RFC 9114 4.1 / 9: view the request body from the first DATA frame after
 * HEADERS, walking past any interleaved unknown/GREASE frame (curl does not
 * place DATA immediately after HEADERS). Reaching the stream end with no DATA
 * is a bodyless request (GET): leave the view empty and succeed. A truncated
 * remainder fails. A request split across multiple DATA frames is not joined
 * (curl/typical clients send one). */
static int find_body(wired_span h3, usz off, wired_h3reqdrive_req* r) {
  while (off < h3.n) {
    int s = body_step(h3, &off, r);
    if (s >= 0) return s;
  }
  return 1;
}

int wired_h3reqdrive_request_sections(
    wired_span stream_data, wired_span* fs, wired_h3reqdrive_req* r) {
  stream_frame f;
  usz          end = 0;
  wired_span   h3;
  if (!frame_get_stream(stream_data.p, stream_data.n, &f)) return 0;
  h3 = wired_span_of(f.data, (usz)f.length);
  if (!find_headers(h3, fs, &end, r)) return 0;
  return find_body(h3, end, r);
}

/* Decode the frame at *off, advancing it past. Returns 1 and stops at a DATA
 * frame (found), 0 on a truncated/undecodable frame, -1 to keep walking (a
 * skipped or unknown frame past HEADERS). Same step shape as body_step but
 * without writing into a request (used only to find the trailer's offset). */
static int body_skip_step(wired_span h3, usz* off) {
  h3_frame f    = {0};
  usz      used = h3_frame_get(wired_span_of(h3.p + *off, h3.n - *off), &f);
  if (!used) return 0;
  *off += used;
  return f.type == H3_FRAME_DATA ? 1 : -1;
}

/* One body_skip_step, folded to "keep walking or not": advances off past the
 * frame at it. Returns 1 to keep walking (a skipped frame, and there is more
 * stream left), 0 to stop -- off then holds the answer: h3.n on truncation
 * (forced past the end, "no trailer here"), or the real stop point on a DATA
 * frame found. */
static int body_walk_step(wired_span h3, usz* off) {
  int s = body_skip_step(h3, off);
  if (s == 0) *off = h3.n; /* truncated: nothing usable follows */
  return s == -1 && *off < h3.n;
}

/* RFC 9114 4.1 / 9: same walk as find_body, but returns the byte offset just
 * past whichever frame stopped the walk (a DATA frame found, or the stream
 * end) -- the point a trailer section (if any) would start from. */
static usz body_end_off(wired_span h3, usz off) {
  while (body_walk_step(h3, &off)) {
  }
  return off;
}

/* View the frame at [off, h3.n) as a trailer HEADERS field section into
 * *trailer_fs. Returns 1 on a HEADERS frame there, 0 if none/truncated/not a
 * HEADERS frame (no trailer section present is reported the same as any
 * other "nothing there" case -- callers treat 0 as "no trailer to check"). */
/* Decode the frame at [off, h3.n) into *tf. 0 if nothing is there or it does
 * not decode -- the two "stop, nothing to check" cases trailer_headers_at's
 * caller shares one return value for. */
static int trailer_frame_at(wired_span h3, usz off, h3_frame* tf) {
  if (off >= h3.n) return 0;
  return h3_frame_get(wired_span_of(h3.p + off, h3.n - off), tf) != 0;
}

static int trailer_headers_at(wired_span h3, usz off, wired_span* trailer_fs) {
  h3_frame tf = {0};
  if (!trailer_frame_at(h3, off, &tf)) return 0;
  if (tf.type != H3_FRAME_HEADERS) return 0;
  *trailer_fs = wired_span_of(tf.payload, (usz)tf.payload_len);
  return 1;
}

int wired_h3reqdrive_request_trailer(
    wired_span stream_data, wired_span* trailer_fs) {
  stream_frame         f;
  wired_span           h3, fs;
  usz                  end     = 0;
  wired_h3reqdrive_req discard = {0}; /* trailer lookup runs after the
                                       * leading HEADERS was already
                                       * accepted once by the caller's own
                                       * wired_h3reqdrive_request_sections
                                       * call -- this walk repeats it only
                                       * to find the trailer's offset, so
                                       * find_headers' reject latch has
                                       * nowhere useful to report to here. */
  if (!frame_get_stream(stream_data.p, stream_data.n, &f)) return 0;
  h3 = wired_span_of(f.data, (usz)f.length);
  if (!find_headers(h3, &fs, &end, &discard)) return 0;
  return trailer_headers_at(h3, body_end_off(h3, end), trailer_fs);
}
