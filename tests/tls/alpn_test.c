#include "test.h"

static void test_alpn_h3_roundtrip(void) {
  const u8  h3[] = {0x68, 0x33};
  u8        buf[16];
  quic_span out;
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  usz       w  = quic_tls_alpn_encode(&ob, quic_span_of(h3, sizeof(h3)));
  usz       r  = quic_tls_alpn_decode_first(quic_span_of(buf, w), &out);
  CHECK(w == 5 && r == w);
  CHECK(out.n == 2 && out.p == buf + 3);
  CHECK(out.p[0] == 0x68 && out.p[1] == 0x33);
  /* wire: list length 0x0003, name length 0x02 */
  CHECK(buf[0] == 0x00 && buf[1] == 0x03 && buf[2] == 0x02);
}

static void test_alpn_truncated(void) {
  const u8  h3[] = {0x68, 0x33};
  u8        buf[16];
  quic_span out;
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  usz       w  = quic_tls_alpn_encode(&ob, quic_span_of(h3, sizeof(h3)));
  /* list length claims 3 but only 2 readable past header */
  CHECK(quic_tls_alpn_decode_first(quic_span_of(buf, w - 1), &out) == 0);
  CHECK(quic_tls_alpn_decode_first(quic_span_of(buf, 2), &out) == 0);
}

static void test_alpn_bad_name_len(void) {
  /* list length 3 but name length 5 overruns the list */
  u8        buf[8] = {0x00, 0x03, 0x05, 0x68, 0x33};
  quic_span out;
  CHECK(quic_tls_alpn_decode_first(quic_span_of(buf, 5), &out) == 0);
}

static void test_alpn_encode_guard(void) {
  const u8  h3[] = {0x68, 0x33};
  u8        buf[4];
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  CHECK(quic_tls_alpn_encode(&ob, quic_span_of(h3, sizeof(h3))) == 0);
  CHECK(quic_tls_alpn_encode(&ob, quic_span_of(h3, 0)) == 0);
}

void test_alpn(void) {
  test_alpn_h3_roundtrip();
  test_alpn_truncated();
  test_alpn_bad_name_len();
  test_alpn_encode_guard();
}
