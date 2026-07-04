#include "transport/packet/frame/pipeline/framewalk.h"

#include "common/bytes/varint/varint.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/dispatch.h"
#include "transport/packet/frame/frame/frame.h"

void quic_framewalk_init(quic_framewalk* it, const u8* frames, usz len) {
  it->cur       = frames;
  it->remaining = len;
}

/* RFC 9000 19.6/19.8/19.19: length of a length-bearing frame via its decoder.
 */
static usz body_len(quic_frame_kind kind, const u8* buf, usz n) {
  quic_crypto_frame     cf;
  quic_stream_frame     sf;
  quic_conn_close_frame ccf;
  if (kind == QUIC_FK_CRYPTO) return quic_frame_get_crypto(buf, n, &cf);
  if (kind == QUIC_FK_STREAM) return quic_frame_get_stream(buf, n, &sf);
  return quic_frame_get_conn_close(buf, n, &ccf);
}

/* Single-byte frames carry no body (RFC 9000 19.1/19.2/19.20). */
static int single_byte(quic_frame_kind kind) {
  return kind == QUIC_FK_PADDING || kind == QUIC_FK_PING ||
         kind == QUIC_FK_HANDSHAKE_DONE;
}

static int has_body(quic_frame_kind kind) {
  return kind == QUIC_FK_CRYPTO || kind == QUIC_FK_STREAM ||
         kind == QUIC_FK_CONNECTION_CLOSE;
}

/* RFC 9000 19.3: an ACK frame's length comes from its own decoder. */
static usz ack_len(const u8* buf, usz n) {
  quic_ack_frame f;
  return quic_ack_decode(buf, n, &f);
}

/* Length of a frame the walker measures via a decoder (ACK or a length-bearing
 * body), or 0 if it carries neither (RFC 9000 19.3/19.6/19.8/19.19). */
static usz decoded_len(quic_frame_kind kind, const u8* buf, usz n) {
  if (kind == QUIC_FK_ACK) return ack_len(buf, n);
  if (has_body(kind)) return body_len(kind, buf, n);
  return 0;
}

/* Bytes the frame at buf occupies, or 0 if the walker cannot measure it. */
static usz frame_len(u64 type, const u8* buf, usz n) {
  quic_frame_kind kind = quic_frame_classify(type);
  if (single_byte(kind)) return 1;
  return decoded_len(kind, buf, n);
}

/* Measure the frame at the cursor, validating it fits. Returns its length or 0.
 */
static usz measure(const quic_framewalk* it, u64* type) {
  usz len;
  if (quic_varint_decode(it->cur, it->remaining, type) == 0) return 0;
  len = frame_len(*type, it->cur, it->remaining);
  return len > it->remaining ? 0 : len;
}

int quic_framewalk_next(quic_framewalk* it, quic_framewalk_item* out) {
  usz len;
  if (it->remaining == 0) return 0;
  len = measure(it, &out->type);
  if (len == 0) return 0;
  out->start     = it->cur;
  out->remaining = it->remaining;
  it->cur += len;
  it->remaining -= len;
  return 1;
}
