#include "tls/ext/salpn/sni_check.h"

#include "chain_golden.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/sni.h"

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

/* A ClientHello offering server_name "x" with byte `at` of its extension
 * data overwritten by v (same length, so every outer length stays valid). */
static usz sni_check_patched_ch(u8* buf, usz cap, usz at, u8 v) {
  wired_span ext;
  usz        w = sni_check_build_ch(wired_span_of((const u8*)"x", 1), buf, cap);
  CHECK(salpn_find_extension(wired_span_of(buf, w), SNI_TYPE, &ext));
  buf[(usz)(ext.p - buf) + at] = v;
  return w;
}

/* RFC 6066 3 / RFC 8446 6.2: a present but unparseable server_name (here an
 * empty HostName followed by a stray byte, or an unknown name_type) is
 * MALFORMED, not ABSENT -- the handshake must not go on as if no SNI. */
static void test_sni_check_malformed(void) {
  u8  buf[512];
  usz w = sni_check_patched_ch(buf, sizeof(buf), 4, 0x00); /* HostName len 0 */
  CHECK(salpn_sni_check(buf, w, golden1_tbs()) == SALPN_SNI_MALFORMED);
  w = sni_check_patched_ch(buf, sizeof(buf), 2, 0x01); /* name_type 1 */
  CHECK(salpn_sni_check(buf, w, golden1_tbs()) == SALPN_SNI_MALFORMED);
}

void test_sni_check(void) {
  test_sni_check_malformed();
  test_sni_check_absent();
  test_sni_check_match();
  test_sni_check_mismatch();
}
