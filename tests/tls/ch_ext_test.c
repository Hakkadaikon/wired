#include "tls/ext/salpn/ch_ext.h"

#include "test.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/sni.h"

static usz build_ch(u8 *buf, usz cap) {
  u8 random[32], pub[32];
  u8 tp[3] = {0x01, 0x02, 0x03};
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    pub[i]    = (u8)(0x40 + i);
  }
  return quic_tls_client_hello(
      buf, cap, random, pub, (const u8 *)"example.com", 11, tp, sizeof(tp));
}

void test_ch_ext_finds_alpn_and_sni(void) {
  u8        buf[512];
  const u8 *data;
  usz       dlen;
  usz       w = build_ch(buf, sizeof(buf));
  CHECK(w > 0);

  CHECK(quic_salpn_find_extension(buf, w, QUIC_SALPN_EXT_TYPE, &data, &dlen));
  CHECK(data >= buf && data + dlen <= buf + w); /* view inside message */

  CHECK(quic_salpn_find_extension(buf, w, QUIC_SNI_TYPE, &data, &dlen));
  CHECK(dlen > 0);
}

void test_ch_ext_absent_returns_zero(void) {
  u8        buf[512];
  const u8 *data;
  usz       dlen;
  usz       w = build_ch(buf, sizeof(buf));
  CHECK(quic_salpn_find_extension(buf, w, 0xABCD, &data, &dlen) == 0);
}

void test_ch_ext_truncated_returns_zero(void) {
  u8        buf[512];
  const u8 *data;
  usz       dlen;
  usz       w = build_ch(buf, sizeof(buf));
  CHECK(
      quic_salpn_find_extension(buf, 3, QUIC_SALPN_EXT_TYPE, &data, &dlen) ==
      0);
  CHECK(
      quic_salpn_find_extension(
          buf, w - 1, QUIC_SALPN_EXT_TYPE, &data, &dlen) == 0);
}
