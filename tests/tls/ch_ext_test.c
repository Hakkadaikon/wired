#include "tls/ext/salpn/ch_ext.h"

#include "test.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/sni.h"

static usz build_ch(u8* buf, usz cap) {
  u8 random[32], pub[32];
  u8 tp[3] = {0x01, 0x02, 0x03};
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    pub[i]    = (u8)(0x40 + i);
  }
  return tls_client_hello(
      &(clienthello_in){
          random, pub, wired_span_of((const u8*)"example.com", 11),
          wired_span_of(tp, sizeof(tp))},
      &(wired_obuf){buf, cap, 0});
}

void test_ch_ext_finds_alpn_and_sni(void) {
  u8         buf[512];
  wired_span ext;
  usz        w = build_ch(buf, sizeof(buf));
  CHECK(w > 0);

  CHECK(salpn_find_extension(wired_span_of(buf, w), SALPN_EXT_TYPE, &ext));
  CHECK(ext.p >= buf && ext.p + ext.n <= buf + w); /* view inside message */

  CHECK(salpn_find_extension(wired_span_of(buf, w), SNI_TYPE, &ext));
  CHECK(ext.n > 0);
}

void test_ch_ext_absent_returns_zero(void) {
  u8         buf[512];
  wired_span ext;
  usz        w = build_ch(buf, sizeof(buf));
  CHECK(salpn_find_extension(wired_span_of(buf, w), 0xABCD, &ext) == 0);
}

void test_ch_ext_truncated_returns_zero(void) {
  u8         buf[512];
  wired_span ext;
  usz        w = build_ch(buf, sizeof(buf));
  CHECK(salpn_find_extension(wired_span_of(buf, 3), SALPN_EXT_TYPE, &ext) == 0);
  CHECK(
      salpn_find_extension(wired_span_of(buf, w - 1), SALPN_EXT_TYPE, &ext) ==
      0);
}
