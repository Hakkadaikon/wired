#include "test.h"

static void test_rebuild_stream_retransmittable(void) {
  const u8   stream[] = {0x08, 0x00, 0x03, 'a', 'b', 'c'};
  u8         out[32];
  wired_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_retransmittable(stream, sizeof stream) == 1);
  CHECK(quic_rtxbytes_rebuild(wired_span_of(stream, sizeof stream), &ob) == 1);
  CHECK(ob.len == sizeof stream);
  for (usz i = 0; i < sizeof stream; i++) CHECK(out[i] == stream[i]);
}

static void test_rebuild_crypto_retransmittable(void) {
  const u8   crypto[] = {0x06, 0x00, 0x02, 0xaa, 0xbb};
  u8         out[32];
  wired_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_retransmittable(crypto, sizeof crypto) == 1);
  CHECK(quic_rtxbytes_rebuild(wired_span_of(crypto, sizeof crypto), &ob) == 1);
  CHECK(ob.len == sizeof crypto);
}

/* RFC 9000 13.3: HANDSHAKE_DONE (0x1e) is ack-eliciting and carries no
 * per-frame state of its own, so it rides the same generic retransmission
 * path as STREAM/CRYPTO -- rebuilt verbatim into a fresh packet when its
 * carrying packet is declared lost, with no HANDSHAKE_DONE-specific code. */
static void test_rebuild_handshake_done_retransmittable(void) {
  const u8   hs_done[] = {0x1e};
  u8         out[32];
  wired_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_retransmittable(hs_done, sizeof hs_done) == 1);
  CHECK(
      quic_rtxbytes_rebuild(wired_span_of(hs_done, sizeof hs_done), &ob) == 1);
  CHECK(ob.len == sizeof hs_done && out[0] == 0x1e);
}

static void test_rebuild_ack_skipped(void) {
  const u8   ack[] = {0x02, 0x00, 0x00, 0x00};
  u8         out[32];
  wired_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_retransmittable(ack, sizeof ack) == 0);
  CHECK(quic_rtxbytes_rebuild(wired_span_of(ack, sizeof ack), &ob) == 1);
  CHECK(ob.len == 0);
}

static void test_rebuild_padding_skipped(void) {
  const u8   pad[] = {0x00, 0x00};
  u8         out[32];
  wired_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_retransmittable(pad, sizeof pad) == 0);
  CHECK(quic_rtxbytes_rebuild(wired_span_of(pad, sizeof pad), &ob) == 1);
  CHECK(ob.len == 0);
}

/* No room to copy a retransmittable frame is an error. */
static void test_rebuild_no_room(void) {
  const u8   stream[] = {0x08, 0x00, 0x01, 'x'};
  u8         out[2];
  wired_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_rebuild(wired_span_of(stream, sizeof stream), &ob) == 0);
}

void test_rebuild(void) {
  test_rebuild_stream_retransmittable();
  test_rebuild_crypto_retransmittable();
  test_rebuild_handshake_done_retransmittable();
  test_rebuild_ack_skipped();
  test_rebuild_padding_skipped();
  test_rebuild_no_room();
}
