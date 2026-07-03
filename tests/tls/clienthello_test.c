#include "test.h"

/* Walk the ClientHello extensions block and return 1 if extension `type` is
 * present. body points at the ClientHello body (after the 4-byte hs header). */
static int ch_has_ext(const u8 *body, usz body_len, unsigned type) {
  usz p = 35 + 4 + 2; /* prefix + cipher_suites(2+2) + compression(1+1) */
  usz block_len, end, q;
  if (body_len < p + 2) return 0;
  block_len = (usz)body[p] << 8 | body[p + 1];
  q         = p + 2;
  end       = q + block_len;
  if (end > body_len) return 0;
  while (q + 4 <= end) {
    unsigned t    = (unsigned)body[q] << 8 | body[q + 1];
    usz      dlen = (usz)body[q + 2] << 8 | body[q + 3];
    if (t == type) return 1;
    q += 4 + dlen;
  }
  return 0;
}

static usz build(u8 *buf, usz cap) {
  u8 random[32], pub[32];
  u8 tp[3] = {0x01, 0x02, 0x03};
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    pub[i]    = (u8)(0x40 + i);
  }
  return quic_tls_client_hello(
      &(quic_clienthello_in){
          random, pub, quic_span_of((const u8 *)"example.com", 11),
          quic_span_of(tp, sizeof(tp))},
      &(quic_obuf){buf, cap, 0});
}

static void test_client_hello_has_all_exts(void) {
  u8  buf[512];
  u8  type;
  usz body_len;
  usz w = build(buf, sizeof(buf));
  CHECK(w > 0);
  CHECK(buf[0] == 1); /* ClientHello */
  CHECK(quic_hs_parse(quic_span_of(buf, w), &type, &body_len) == 4);
  CHECK(type == 1);
  CHECK(ch_has_ext(buf + 4, body_len, 0x002b)); /* supported_versions */
  CHECK(ch_has_ext(buf + 4, body_len, 0x000a)); /* supported_groups */
  CHECK(ch_has_ext(buf + 4, body_len, 0x000d)); /* signature_algorithms */
  CHECK(ch_has_ext(buf + 4, body_len, 0x0033)); /* key_share */
  CHECK(ch_has_ext(buf + 4, body_len, 0x0000)); /* server_name */
  CHECK(ch_has_ext(buf + 4, body_len, 0x0010)); /* ALPN */
  CHECK(ch_has_ext(buf + 4, body_len, 0x0039)); /* quic_transport_parameters */
}

static void test_client_hello_no_sni(void) {
  u8  buf[512], random[32], pub[32];
  u8  tp[2] = {0xff, 0x00};
  usz w;
  for (usz i = 0; i < 32; i++) {
    random[i] = 0;
    pub[i]    = 0;
  }
  w = quic_tls_client_hello(
      &(quic_clienthello_in){random, pub, quic_span_of(0, 0), quic_span_of(tp, 2)},
      &(quic_obuf){buf, sizeof(buf), 0});
  CHECK(w > 0);
  CHECK(!ch_has_ext(buf + 4, w - 4, 0x0000)); /* SNI omitted */
  CHECK(ch_has_ext(buf + 4, w - 4, 0x0033));  /* key_share still present */
}

static void test_client_hello_cap_guard(void) {
  u8 small[40];
  CHECK(build(small, sizeof(small)) == 0);
}

void test_clienthello(void) {
  test_client_hello_has_all_exts();
  test_client_hello_no_sni();
  test_client_hello_cap_guard();
}
