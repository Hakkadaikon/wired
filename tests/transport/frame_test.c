#include "test.h"

static void test_frame_simple(void) {
  u8 buf[4];
  CHECK(
      quic_frame_put_simple(buf, sizeof(buf), QUIC_FRAME_PING) == 1 &&
      buf[0] == 0x01);
  CHECK(
      quic_frame_put_simple(buf, sizeof(buf), QUIC_FRAME_PADDING) == 1 &&
      buf[0] == 0x00);
  CHECK(quic_frame_put_simple(buf, 0, QUIC_FRAME_PING) == 0);
}

static void test_frame_crypto_roundtrip(void) {
  const u8          payload[] = {0x16, 0x03, 0x03, 0xAA, 0xBB};
  quic_crypto_frame in        = {
      .offset = 1000, .length = sizeof(payload), .data = payload};
  u8  buf[32];
  usz w = quic_frame_put_crypto(buf, sizeof(buf), &in);
  CHECK(w != 0 && buf[0] == QUIC_FRAME_CRYPTO);

  quic_crypto_frame out;
  usz               r = quic_frame_get_crypto(buf, w, &out);
  CHECK(r == w && out.offset == 1000 && out.length == sizeof(payload));
  CHECK(out.data[0] == 0x16 && out.data[4] == 0xBB);
}

static void test_frame_crypto_truncated(void) {
  const u8          payload[] = {1, 2, 3};
  quic_crypto_frame in        = {.offset = 0, .length = 3, .data = payload};
  u8                buf[32];
  usz               w = quic_frame_put_crypto(buf, sizeof(buf), &in);
  quic_crypto_frame out;
  CHECK(quic_frame_get_crypto(buf, w - 1, &out) == 0); /* data cut short */
  CHECK(quic_frame_put_crypto(buf, 2, &in) == 0);      /* header no room */
}

static void check_stream_roundtrip(u64 sid, u64 off, u8 fin) {
  const u8          payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
  quic_stream_frame in        = {
      .stream_id = sid,
      .offset    = off,
      .length    = sizeof(payload),
      .data      = payload,
      .fin       = fin};
  u8  buf[32];
  usz w = quic_frame_put_stream(buf, sizeof(buf), &in);
  CHECK(w != 0 && (buf[0] & 0xF8) == QUIC_FRAME_STREAM_BASE);

  quic_stream_frame out;
  usz               r = quic_frame_get_stream(buf, w, &out);
  CHECK(r == w && out.stream_id == sid && out.offset == off);
  CHECK(out.length == sizeof(payload) && out.fin == fin);
  CHECK(out.data[0] == 0xDE && out.data[3] == 0xEF);
}

static void test_frame_stream(void) {
  check_stream_roundtrip(4, 0, 0);    /* no offset, no fin */
  check_stream_roundtrip(8, 1000, 1); /* offset + fin */
  check_stream_roundtrip(0, 0, 1);    /* stream 0, fin, no offset */
}

static void test_frame_stream_truncated(void) {
  const u8          payload[] = {1, 2, 3};
  quic_stream_frame in        = {
      .stream_id = 4, .offset = 5, .length = 3, .data = payload, .fin = 0};
  u8                buf[32];
  usz               w = quic_frame_put_stream(buf, sizeof(buf), &in);
  quic_stream_frame out;
  CHECK(quic_frame_get_stream(buf, w - 1, &out) == 0);
  CHECK(quic_frame_put_stream(buf, 2, &in) == 0);
}

static void test_frame_conn_close(void) {
  const u8 reason[] = "bye";
  /* transport variant: carries frame_type */
  quic_conn_close_frame tpt = {
      .is_app     = 0,
      .error_code = 0x0a,
      .frame_type = QUIC_FRAME_STREAM_BASE,
      .reason_len = 3,
      .reason     = reason};
  u8  buf[32];
  usz w = quic_frame_put_conn_close(buf, sizeof(buf), &tpt);
  CHECK(w != 0 && buf[0] == QUIC_FRAME_CONN_CLOSE_TPT);
  quic_conn_close_frame out;
  usz                   r = quic_frame_get_conn_close(buf, w, &out);
  CHECK(r == w && out.is_app == 0 && out.error_code == 0x0a);
  CHECK(out.frame_type == QUIC_FRAME_STREAM_BASE && out.reason_len == 3);
  CHECK(out.reason[0] == 'b' && out.reason[2] == 'e');

  /* application variant: no frame_type field */
  quic_conn_close_frame app = {
      .is_app = 1, .error_code = 0x100, .reason_len = 0, .reason = reason};
  usz wa = quic_frame_put_conn_close(buf, sizeof(buf), &app);
  CHECK(wa != 0 && buf[0] == QUIC_FRAME_CONN_CLOSE_APP);
  quic_conn_close_frame outa;
  CHECK(quic_frame_get_conn_close(buf, wa, &outa) == wa);
  CHECK(outa.is_app == 1 && outa.error_code == 0x100 && outa.reason_len == 0);
}

/* RFC 9000 19.8: a STREAM frame without the LEN bit (0x02) carries no Length
 * field -- its data extends to the end of the packet. Chrome ships its
 * CONNECT HEADERS exactly this way (the last frame of the packet); reading a
 * phantom Length varint out of the data's first byte truncated that request
 * to one byte and no browser session could ever be established. */
static void test_frame_stream_implicit_length(void) {
  /* type 0x08 (no OFF/LEN/FIN), stream id 0, then 5 data bytes */
  const u8          buf[] = {0x08, 0x00, 0x01, 0x40, 0x51, 0x00, 0x1d};
  quic_stream_frame f;
  usz               r = quic_frame_get_stream(buf, sizeof buf, &f);
  CHECK(r == sizeof buf);
  CHECK(f.stream_id == 0 && f.offset == 0 && f.fin == 0);
  CHECK(f.length == 5);
  CHECK(f.data[0] == 0x01 && f.data[4] == 0x1d);

  /* OFF set, LEN absent: offset varint then data to the end */
  const u8 buf2[] = {0x0c, 0x04, 0x08, 0xaa, 0xbb};
  r               = quic_frame_get_stream(buf2, sizeof buf2, &f);
  CHECK(r == sizeof buf2);
  CHECK(f.stream_id == 4 && f.offset == 8 && f.length == 2);
  CHECK(f.data[0] == 0xaa && f.data[1] == 0xbb);
}

void test_frame(void) {
  test_frame_simple();
  test_frame_crypto_roundtrip();
  test_frame_crypto_truncated();
  test_frame_stream();
  test_frame_stream_truncated();
  test_frame_stream_implicit_length();
  test_frame_conn_close();
}
