#include "test.h"

/* A built ClientHello parses back with the right type and yields the share. */
static void test_hs_clienthello_roundtrip(void) {
  u8 random[32], pub[32], out[256];
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    pub[i]    = (u8)(0x40 + i);
  }
  usz total =
      quic_hs_build_hello(out, sizeof(out), QUIC_HS_CLIENT_HELLO, random, pub);
  CHECK(total != 0 && out[0] == QUIC_HS_CLIENT_HELLO);

  u8  type;
  usz body_len;
  usz body = quic_hs_parse(quic_span_of(out, total), &type, &body_len);
  CHECK(body == 4 && type == QUIC_HS_CLIENT_HELLO && body_len == total - 4);

  u8 got[32];
  CHECK(quic_hs_peer_share(out + body, body_len, got) == 1);
  for (usz i = 0; i < 32; i++) CHECK(got[i] == pub[i]);
}

/* ServerHello uses the same framing and also round-trips its share. */
static void test_hs_serverhello_roundtrip(void) {
  u8 random[32], pub[32], out[256], got[32];
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)(i * 2);
    pub[i]    = (u8)(0x90 + i);
  }
  usz total =
      quic_hs_build_hello(out, sizeof(out), QUIC_HS_SERVER_HELLO, random, pub);
  u8  type;
  usz body_len;
  usz body = quic_hs_parse(quic_span_of(out, total), &type, &body_len);
  CHECK(type == QUIC_HS_SERVER_HELLO);
  CHECK(quic_hs_peer_share(out + body, body_len, got) == 1 && got[5] == pub[5]);
}

static void test_hs_truncated(void) {
  u8       type;
  usz      body_len;
  const u8 bad[3] = {1, 0, 5};
  CHECK(quic_hs_parse(quic_span_of(bad, 3), &type, &body_len) == 0);
  /* claims body 100 but only 4 bytes present */
  const u8 bad2[4] = {1, 0, 0, 100};
  CHECK(quic_hs_parse(quic_span_of(bad2, 4), &type, &body_len) == 0);
}

void test_handshake(void) {
  test_hs_clienthello_roundtrip();
  test_hs_serverhello_roundtrip();
  test_hs_truncated();
}
