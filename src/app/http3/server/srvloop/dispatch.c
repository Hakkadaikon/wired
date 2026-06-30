#include "app/http3/server/srvloop/dispatch.h"

#include "app/http3/server/h3srv/respond.h"
#include "common/bytes/util/bytes.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9000 19.8: STREAM frame types occupy 0x08..0x0f. */
static int is_stream(u64 type) {
  return type >= QUIC_FRAME_STREAM_BASE && type <= QUIC_FRAME_STREAM_BASE + 7;
}

/* RFC 9000 2.1: a STREAM is a client-initiated bidirectional request stream
 * (carrying HTTP/3 HEADERS) iff its low two bits are 0. The 0x2 bit marks a
 * unidirectional stream (HTTP/3 control / QPACK encoder+decoder, RFC 9114 6.2),
 * which curl opens before the request and must NOT be treated as a request. */
static int is_request_stream(u64 stream_id) { return (stream_id & 0x03) == 0; }

/* 1 if the STREAM frame at `frame` is a client bidi request stream. */
static int stream_is_request(const u8 *frame, usz rem) {
  quic_stream_frame sf;
  if (quic_frame_get_stream(frame, rem, &sf) == 0) return 0;
  return is_request_stream(sf.stream_id);
}

/* 1 if the walked frame of `type` at `frame` is a client bidi request STREAM.
 */
static int is_request_frame(u64 type, const u8 *frame, usz rem) {
  return is_stream(type) && stream_is_request(frame, rem);
}

/* RFC 9114 4.1: hand the (reassembled) request STREAM frame to the HTTP/3
 * request decoder. */
static int dispatch_stream(
    quic_h3srv_state    *h3,
    const u8            *frame,
    usz                  len,
    u8                  *scratch,
    usz                  scap,
    int                 *got_request,
    quic_h3reqdrive_req *req) {
  if (!quic_h3srv_on_request(h3, frame, len, scratch, scap, req)) return 0;
  *got_request = 1;
  return 1;
}

/* Raise the accumulator high-water mark to end, clamped to acc->cap. */
static void bump_len(quic_srvloop_reqacc *acc, usz end) {
  usz hi = end < acc->cap ? end : acc->cap;
  if (hi > *acc->len) *acc->len = hi;
}

/* RFC 9000 2.2: write one request STREAM frame's data into acc->buf at the
 * frame's own offset (offset-indexed reassembly, robust to reordering within
 * acc->cap), advance the high-water mark, and OR its FIN into acc->fin.
 * ponytail: data past acc->cap is truncated. */
static void gather_one(const quic_stream_frame *sf, quic_srvloop_reqacc *acc) {
  usz off = (usz)sf->offset;
  if (off >= acc->cap) return;
  quic_put_bytes(acc->buf, acc->cap, &off, sf->data, (usz)sf->length);
  bump_len(acc, (usz)sf->offset + (usz)sf->length);
  *acc->fin |= sf->fin;
}

/* 1 if the walked frame is a request STREAM frame and decodes into sf. */
static int request_stream_of(
    u64 type, const u8 *frame, usz rem, quic_stream_frame *sf) {
  return is_request_frame(type, frame, rem) &&
         quic_frame_get_stream(frame, rem, sf);
}

/* RFC 9000 2.2 / 12.4, RFC 9114 6.2: write every client bidi (request) STREAM
 * frame in this payload into the cross-datagram accumulator at its offset,
 * skipping PADDING/ACK and the unidirectional STREAMs (control / QPACK) curl
 * sends first. Returns 1 if any request-stream frame was seen this datagram. */
static int gather_request(
    const u8 *payload, usz len, quic_srvloop_reqacc *acc) {
  quic_framewalk    it;
  u64               type;
  const u8         *frame;
  usz               rem;
  int               seen = 0;
  quic_stream_frame sf;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &type, &frame, &rem))
    if (request_stream_of(type, frame, rem, &sf)) {
      gather_one(&sf, acc);
      seen = 1;
    }
  return seen;
}

/* RFC 9000 2.2: the request is complete once FIN closed the stream and it has
 * not already been decoded/answered (curl FINs the request's last STREAM). */
static int request_complete(const quic_srvloop_reqacc *acc) {
  return *acc->fin && !*acc->done;
}

/* RFC 9114 4.1: re-wrap the reassembled stream bytes as a single STREAM frame
 * (offset 0) and drive the HTTP/3 request decoder once. */
static void drive_complete(
    quic_h3srv_state    *h3,
    quic_srvloop_reqacc *acc,
    u8                  *scratch,
    usz                  scap,
    int                 *got_request,
    quic_h3reqdrive_req *req) {
  u8  wrap[2080];
  usz wlen   = 0;
  *acc->done = 1;
  if (quic_appdata_stream_frame(
          0, 0, acc->buf, *acc->len, 1, wrap, sizeof wrap, &wlen))
    dispatch_stream(h3, wrap, wlen, scratch, scap, got_request, req);
}

/* RFC 9000 2.2 / RFC 9114 4.1: accumulate this payload's request-stream frames;
 * once FIN closes the stream, decode the reassembled request exactly once.
 * Returns 1 if a request-stream frame was present (handled), 0 otherwise. */
static int reassemble_and_drive(
    quic_h3srv_state    *h3,
    const u8            *payload,
    usz                  len,
    quic_srvloop_reqacc *acc,
    u8                  *scratch,
    usz                  scap,
    int                 *got_request,
    quic_h3reqdrive_req *req) {
  if (!gather_request(payload, len, acc)) return 0;
  if (request_complete(acc))
    drive_complete(h3, acc, scratch, scap, got_request, req);
  return 1;
}

/* 1 if the payload carries a STREAM frame of any kind (request or uni). Such a
 * 1-RTT payload belongs to the HTTP/3 path and must never re-enter the
 * handshake via quic_server_feed (RFC 9000 12.4). */
static int has_stream(const u8 *payload, usz len) {
  quic_framewalk it;
  u64            type;
  const u8      *frame;
  usz            rem;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &type, &frame, &rem))
    if (is_stream(type)) return 1;
  return 0;
}

/* 1 if the payload carries at least one walkable frame (non-empty, decodes).
 * An empty/undecodable payload drives nothing. */
static int has_frame(const u8 *payload, usz len) {
  quic_framewalk it;
  u64            type;
  const u8      *frame;
  usz            rem;
  quic_framewalk_init(&it, payload, len);
  return quic_framewalk_next(&it, &type, &frame, &rem);
}

/* No request stream found. A payload carrying only unidirectional STREAM frames
 * (curl's control / QPACK, RFC 9114 6.2) is accepted but drives no request; a
 * CRYPTO/handshake payload is handed to quic_server_feed. */
static int feed_or_accept(quic_server *s, const u8 *payload, usz len) {
  if (has_stream(payload, len)) return 1;
  return quic_server_feed(s, payload, len);
}

static int dispatch_non_request(quic_server *s, const u8 *payload, usz len) {
  if (!has_frame(payload, len)) return 0;
  return feed_or_accept(s, payload, len);
}

/* RFC 9000 12.4 / 2.1, RFC 9114 6.2: a payload may lead with PADDING/ACK before
 * its CRYPTO or STREAM frame (curl/quiche do this). A client bidi STREAM drives
 * HTTP/3; unidirectional STREAMs are accepted but ignored; anything else is
 * handed whole to quic_server_feed, whose crecv reassembles a split
 * ClientHello/Finished. A STREAM payload never re-enters the handshake. */
int quic_srvloop_dispatch(
    quic_server         *s,
    quic_h3srv_state    *h3,
    const u8            *payload,
    usz                  len,
    quic_srvloop_reqacc *acc,
    u8                  *scratch,
    usz                  scap,
    int                 *got_request,
    quic_h3reqdrive_req *req) {
  if (reassemble_and_drive(
          h3, payload, len, acc, scratch, scap, got_request, req))
    return 1;
  return dispatch_non_request(s, payload, len);
}
