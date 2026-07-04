#include "tls/ext/salpn/negotiate.h"

#include "test.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/handshake/core/tls/clienthello.h"

/* ProtocolNameList: list_len(2) (name_len(1) name)* */

void test_negotiate_selects_h3_from_clienthello(void) {
  u8        buf[512], random[32], pub[32];
  u8        tp[3] = {0x01, 0x02, 0x03};
  quic_span ext;
  usz       w;
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    pub[i]    = (u8)(0x40 + i);
  }
  w = quic_tls_client_hello(
      &(quic_clienthello_in){random, pub, quic_span_of(0, 0),
                             quic_span_of(tp, sizeof(tp))},
      &(quic_obuf){buf, sizeof(buf), 0});
  CHECK(quic_salpn_find_extension(
      quic_span_of(buf, w), QUIC_SALPN_EXT_TYPE, &ext));
  CHECK(quic_salpn_select_h3(ext.p, ext.n) == 1);
}

void test_negotiate_rejects_non_h3(void) {
  /* list_len=3, name_len=2, "h2" */
  u8 list[5] = {0x00, 0x03, 0x02, 0x68, 0x32};
  CHECK(quic_salpn_select_h3(list, sizeof(list)) == 0);
}

void test_negotiate_h3_among_others(void) {
  /* "h2" then "h3" */
  u8 list[8] = {0x00, 0x06, 0x02, 0x68, 0x32, 0x02, 0x68, 0x33};
  CHECK(quic_salpn_select_h3(list, sizeof(list)) == 1);
}

void test_negotiate_truncated(void) {
  u8 list[4] = {0x00, 0x06, 0x02, 0x68}; /* list_len lies past buffer */
  CHECK(quic_salpn_select_h3(list, sizeof(list)) == 0);
  CHECK(quic_salpn_select_h3(list, 1) == 0);
}

void test_negotiate_build_response(void) {
  u8              out[16];
  usz             n;
  static const u8 want[9] = {0x00, 0x10, 0x00, 0x05, 0x00,
                             0x03, 0x02, 0x68, 0x33};
  CHECK(quic_salpn_build_response(out, sizeof(out), &n) == 1);
  CHECK(n == 9);
  for (usz i = 0; i < 9; i++) CHECK(out[i] == want[i]);
  CHECK(quic_salpn_build_response(out, 8, &n) == 0); /* too small */
}
