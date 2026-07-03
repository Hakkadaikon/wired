#include "test.h"

static void test_sni_roundtrip(void) {
  const u8  host[] = {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
  u8        buf[32];
  quic_span out;
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  usz       w  = quic_tls_sni_encode(&ob, quic_span_of(host, sizeof(host)));
  usz       r  = quic_tls_sni_decode(quic_span_of(buf, w), &out);
  CHECK(w == 3 + sizeof(host) && r == w);
  CHECK(out.n == sizeof(host) && out.p == buf + 3);
  for (usz i = 0; i < sizeof(host); i++) CHECK(out.p[i] == host[i]);
  /* wire: name_type host_name, length */
  CHECK(buf[0] == 0x00);
  CHECK(buf[1] == 0x00 && buf[2] == (u8)sizeof(host));
}

static void test_sni_truncated(void) {
  const u8  host[] = {'a', 'b', 'c'};
  u8        buf[16];
  quic_span out;
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  usz       w  = quic_tls_sni_encode(&ob, quic_span_of(host, sizeof(host)));
  /* length claims 3 but only 2 data bytes readable */
  CHECK(quic_tls_sni_decode(quic_span_of(buf, w - 1), &out) == 0);
  /* short header */
  CHECK(quic_tls_sni_decode(quic_span_of(buf, 2), &out) == 0);
}

static void test_sni_wrong_type(void) {
  u8        buf[8] = {0x01, 0x00, 0x00};
  quic_span out;
  CHECK(quic_tls_sni_decode(quic_span_of(buf, 3), &out) == 0);
}

static void test_sni_no_room(void) {
  const u8  host[] = {'a', 'b', 'c'};
  u8        buf[4];
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  CHECK(quic_tls_sni_encode(&ob, quic_span_of(host, sizeof(host))) == 0);
}

void test_sni(void) {
  test_sni_roundtrip();
  test_sni_truncated();
  test_sni_wrong_type();
  test_sni_no_room();
}
