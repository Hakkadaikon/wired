#include "app/http3/request/h3reqdrive/request_parse.h"

#include "app/http3/core/h3/frame.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9114 9 / 7.2.8: walk the request stream's HTTP/3 frames, skipping any
 * unknown/reserved frame (e.g. the GREASE frame curl/quiche send), until the
 * HEADERS frame is found; view its field-section payload in place. Returns 1
 * if a HEADERS frame is reached, 0 if the stream ends or is truncated. */
static int find_headers(quic_span h3, quic_span* fs, usz* end) {
  quic_h3_frame f   = {0};
  usz           off = 0;
  while (f.type != QUIC_H3_FRAME_HEADERS) {
    usz used = quic_h3_frame_get(quic_span_of(h3.p + off, h3.n - off), &f);
    if (!used) return 0;
    off += used;
  }
  *fs  = quic_span_of(f.payload, (usz)f.payload_len);
  *end = off;
  return 1;
}

/* Decode the frame at cur->off; on a DATA frame view its body into r and
 * stop. Returns 1 when DATA is found (cur->off advanced past it is
 * irrelevant then), 0 on a truncated/undecodable frame, -1 to keep walking
 * (a skipped frame). */
static int body_step(quic_span h3, usz* off, wired_h3reqdrive_req* r) {
  quic_h3_frame f = {0};
  usz used = quic_h3_frame_get(quic_span_of(h3.p + *off, h3.n - *off), &f);
  if (!used) return 0;
  *off += used;
  if (f.type != QUIC_H3_FRAME_DATA) return -1;
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
static int find_body(quic_span h3, usz off, wired_h3reqdrive_req* r) {
  while (off < h3.n) {
    int s = body_step(h3, &off, r);
    if (s >= 0) return s;
  }
  return 1;
}

int wired_h3reqdrive_request_sections(
    quic_span stream_data, quic_span* fs, wired_h3reqdrive_req* r) {
  quic_stream_frame f;
  usz               end = 0;
  quic_span         h3;
  if (!quic_frame_get_stream(stream_data.p, stream_data.n, &f)) return 0;
  h3 = quic_span_of(f.data, (usz)f.length);
  if (!find_headers(h3, fs, &end)) return 0;
  return find_body(h3, end, r);
}

/* Decode the frame at *off, advancing it past. Returns 1 and stops at a DATA
 * frame (found), 0 on a truncated/undecodable frame, -1 to keep walking (a
 * skipped or unknown frame past HEADERS). Same step shape as body_step but
 * without writing into a request (used only to find the trailer's offset). */
static int body_skip_step(quic_span h3, usz* off) {
  quic_h3_frame f = {0};
  usz used = quic_h3_frame_get(quic_span_of(h3.p + *off, h3.n - *off), &f);
  if (!used) return 0;
  *off += used;
  return f.type == QUIC_H3_FRAME_DATA ? 1 : -1;
}

/* One body_skip_step, folded to "keep walking or not": advances off past the
 * frame at it. Returns 1 to keep walking (a skipped frame, and there is more
 * stream left), 0 to stop -- off then holds the answer: h3.n on truncation
 * (forced past the end, "no trailer here"), or the real stop point on a DATA
 * frame found. */
static int body_walk_step(quic_span h3, usz* off) {
  int s = body_skip_step(h3, off);
  if (s == 0) *off = h3.n; /* truncated: nothing usable follows */
  return s == -1 && *off < h3.n;
}

/* RFC 9114 4.1 / 9: same walk as find_body, but returns the byte offset just
 * past whichever frame stopped the walk (a DATA frame found, or the stream
 * end) -- the point a trailer section (if any) would start from. */
static usz body_end_off(quic_span h3, usz off) {
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
static int trailer_frame_at(quic_span h3, usz off, quic_h3_frame* tf) {
  if (off >= h3.n) return 0;
  return quic_h3_frame_get(quic_span_of(h3.p + off, h3.n - off), tf) != 0;
}

static int trailer_headers_at(quic_span h3, usz off, quic_span* trailer_fs) {
  quic_h3_frame tf = {0};
  if (!trailer_frame_at(h3, off, &tf)) return 0;
  if (tf.type != QUIC_H3_FRAME_HEADERS) return 0;
  *trailer_fs = quic_span_of(tf.payload, (usz)tf.payload_len);
  return 1;
}

int wired_h3reqdrive_request_trailer(
    quic_span stream_data, quic_span* trailer_fs) {
  quic_stream_frame f;
  quic_span         h3, fs;
  usz               end = 0;
  if (!quic_frame_get_stream(stream_data.p, stream_data.n, &f)) return 0;
  h3 = quic_span_of(f.data, (usz)f.length);
  if (!find_headers(h3, &fs, &end)) return 0;
  return trailer_headers_at(h3, body_end_off(h3, end), trailer_fs);
}
