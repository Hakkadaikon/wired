#include "test.h"

static void test_rebuild_stream_retransmittable(void) {
  const u8  stream[] = {0x08, 0x00, 0x03, 'a', 'b', 'c'};
  u8        out[32];
  quic_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_retransmittable(stream, sizeof stream) == 1);
  CHECK(quic_rtxbytes_rebuild(quic_span_of(stream, sizeof stream), &ob) == 1);
  CHECK(ob.len == sizeof stream);
  for (usz i = 0; i < sizeof stream; i++) CHECK(out[i] == stream[i]);
}

static void test_rebuild_crypto_retransmittable(void) {
  const u8  crypto[] = {0x06, 0x00, 0x02, 0xaa, 0xbb};
  u8        out[32];
  quic_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_retransmittable(crypto, sizeof crypto) == 1);
  CHECK(quic_rtxbytes_rebuild(quic_span_of(crypto, sizeof crypto), &ob) == 1);
  CHECK(ob.len == sizeof crypto);
}

static void test_rebuild_ack_skipped(void) {
  const u8  ack[] = {0x02, 0x00, 0x00, 0x00};
  u8        out[32];
  quic_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_retransmittable(ack, sizeof ack) == 0);
  CHECK(quic_rtxbytes_rebuild(quic_span_of(ack, sizeof ack), &ob) == 1);
  CHECK(ob.len == 0);
}

static void test_rebuild_padding_skipped(void) {
  const u8  pad[] = {0x00, 0x00};
  u8        out[32];
  quic_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_retransmittable(pad, sizeof pad) == 0);
  CHECK(quic_rtxbytes_rebuild(quic_span_of(pad, sizeof pad), &ob) == 1);
  CHECK(ob.len == 0);
}

/* No room to copy a retransmittable frame is an error. */
static void test_rebuild_no_room(void) {
  const u8  stream[] = {0x08, 0x00, 0x01, 'x'};
  u8        out[2];
  quic_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_rtxbytes_rebuild(quic_span_of(stream, sizeof stream), &ob) == 0);
}

void test_rebuild(void) {
  test_rebuild_stream_retransmittable();
  test_rebuild_crypto_retransmittable();
  test_rebuild_ack_skipped();
  test_rebuild_padding_skipped();
  test_rebuild_no_room();
}
