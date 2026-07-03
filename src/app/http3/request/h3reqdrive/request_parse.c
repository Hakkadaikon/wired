#include "app/http3/request/h3reqdrive/request_parse.h"

#include "app/http3/core/h3/frame.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9114 9 / 7.2.8: walk the request stream's HTTP/3 frames, skipping any
 * unknown/reserved frame (e.g. the GREASE frame curl/quiche send), until the
 * HEADERS frame is found; view its field-section payload in place. Returns 1
 * if a HEADERS frame is reached, 0 if the stream ends or is truncated. */
static int find_headers(quic_span h3, quic_span *fs, usz *end) {
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
static int body_step(quic_span h3, usz *off, quic_h3reqdrive_req *r) {
  quic_h3_frame f    = {0};
  usz           used = quic_h3_frame_get(quic_span_of(h3.p + *off, h3.n - *off), &f);
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
static int find_body(quic_span h3, usz off, quic_h3reqdrive_req *r) {
  while (off < h3.n) {
    int s = body_step(h3, &off, r);
    if (s >= 0) return s;
  }
  return 1;
}

int quic_h3reqdrive_request_sections(
    quic_span stream_data, quic_span *fs, quic_h3reqdrive_req *r) {
  quic_stream_frame f;
  usz               end = 0;
  quic_span         h3;
  if (!quic_frame_get_stream(stream_data.p, stream_data.n, &f)) return 0;
  h3 = quic_span_of(f.data, (usz)f.length);
  if (!find_headers(h3, fs, &end)) return 0;
  return find_body(h3, end, r);
}
