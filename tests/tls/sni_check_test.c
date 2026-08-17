#include "tls/ext/salpn/sni_check.h"

#include "chain_golden.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"
#include "tls/handshake/core/tls/clienthello.h"

/* golden1: subject/SAN example.com + *.example.com. */
static wired_span golden1_tbs(void) {
  x509 c;
  CHECK(
      x509_parse(wired_span_of(chain_golden1, sizeof(chain_golden1)), &c) == 1);
  return c.tbs;
}

static usz sni_check_build_ch(wired_span sni, u8* buf, usz cap) {
  u8 random[32], pub[32];
  u8 tp[3] = {0x01, 0x02, 0x03};
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    pub[i]    = (u8)(0x40 + i);
  }
  return tls_client_hello(
      &(clienthello_in){random, pub, sni, wired_span_of(tp, sizeof(tp))},
      &(wired_obuf){buf, cap, 0});
}

/* RFC 6066 3: no server_name extension at all -> ABSENT, never a mismatch. */
static void test_sni_check_absent(void) {
  u8  buf[512];
  usz w = sni_check_build_ch(wired_span_of(0, 0), buf, sizeof(buf));
  CHECK(w > 0);
  CHECK(salpn_sni_check(buf, w, golden1_tbs()) == SALPN_SNI_ABSENT);
}

/* Offered name matches a SAN dNSName. */
static void test_sni_check_match(void) {
  u8       buf[512];
  const u8 host[] = "example.com";
  usz      w      = sni_check_build_ch(
      wired_span_of(host, sizeof(host) - 1), buf, sizeof(buf));
  CHECK(w > 0);
  CHECK(salpn_sni_check(buf, w, golden1_tbs()) == SALPN_SNI_MATCH);
}

/* Offered name matches neither the SAN entries nor (since SAN is present,
 * RFC 6125 6.4.4) the CN. */
static void test_sni_check_mismatch(void) {
  u8       buf[512];
  const u8 host[] = "unrelated.example";
  usz      w      = sni_check_build_ch(
      wired_span_of(host, sizeof(host) - 1), buf, sizeof(buf));
  CHECK(w > 0);
  CHECK(salpn_sni_check(buf, w, golden1_tbs()) == SALPN_SNI_MISMATCH);
}

void test_sni_check(void) {
  test_sni_check_absent();
  test_sni_check_match();
  test_sni_check_mismatch();
}
