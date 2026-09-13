#include "test.h"

/* Build a minimal ServerHello (RFC 8446 4.1.3) carrying supported_versions and
 * a single x25519 key_share entry. Returns total message length. */
static usz build_sh(u8* out, usz cap, const u8 pub[32]) {
  usz off = hs_begin(out, cap, 2);
  usz block, end;
  out[off]     = 0x03;
  out[off + 1] = 0x03; /* legacy_version */
  for (usz i = 0; i < 32; i++) out[off + 2 + i] = (u8)(0x10 + i); /* random */
  out[off + 34] = 0; /* session_id len */
  out[off + 35] = 0x13;
  out[off + 36] = 0x01; /* cipher_suite */
  out[off + 37] = 0;    /* compression */
  block         = off + 38;
  off           = block + 2;
  /* supported_versions: type 002b, len 2, TLS 1.3 */
  out[off]     = 0x00;
  out[off + 1] = 0x2b;
  out[off + 2] = 0x00;
  out[off + 3] = 2;
  out[off + 4] = 0x03;
  out[off + 5] = 0x04;
  off += 6;
  /* key_share: type 0033, len 36, group 001d, ke_len 32, key */
  out[off]     = 0x00;
  out[off + 1] = 0x33;
  out[off + 2] = 0x00;
  out[off + 3] = 36;
  out[off + 4] = 0x00;
  out[off + 5] = 0x1d;
  out[off + 6] = 0x00;
  out[off + 7] = 32;
  for (usz i = 0; i < 32; i++) out[off + 8 + i] = pub[i];
  off += 40;
  out[block]     = (u8)((off - block - 2) >> 8);
  out[block + 1] = (u8)(off - block - 2);
  hs_finish(out, off);
  (void)cap;
  (void)end;
  return off;
}

static void test_server_hello_roundtrip(void) {
  u8              pub[32], got[32], buf[256];
  serverhello_out sh = {0, 0};
  for (usz i = 0; i < 32; i++) pub[i] = (u8)(0x80 + i);
  usz w = build_sh(buf, sizeof(buf), pub);
  CHECK(tls_parse_server_hello(wired_span_of(buf, w), got, &sh) == 1);
  CHECK(sh.cipher == 0x1301);
  CHECK(sh.version == 0x0304);
  for (usz i = 0; i < 32; i++) CHECK(got[i] == pub[i]);
}

static void test_server_hello_wrong_type(void) {
  u8              pub[32] = {0}, got[32], buf[256];
  serverhello_out sh;
  usz             w = build_sh(buf, sizeof(buf), pub);
  buf[0]            = 1; /* claim ClientHello */
  CHECK(tls_parse_server_hello(wired_span_of(buf, w), got, &sh) == 0);
}

static void test_server_hello_truncated(void) {
  u8              pub[32] = {0}, got[32], buf[256];
  serverhello_out sh;
  usz             w = build_sh(buf, sizeof(buf), pub);
  CHECK(tls_parse_server_hello(wired_span_of(buf, w - 10), got, &sh) == 0);
}

/* RFC 8446 4.1.3/4.2.1 (Appendix D.1): a ServerHello without a
 * supported_versions extension is a pre-1.3 negotiation this TLS-1.3-only
 * client MUST reject. Mutating the extension type makes it unrecognized, so
 * no selected version is ever taken. */
static void test_server_hello_rejects_missing_supported_versions(void) {
  u8              pub[32] = {0}, got[32], buf[256];
  serverhello_out sh;
  usz             w = build_sh(buf, sizeof(buf), pub);
  buf[44]           = 0x7a; /* supported_versions type -> unknown */
  buf[45]           = 0x7a;
  CHECK(tls_parse_server_hello(wired_span_of(buf, w), got, &sh) == 0);
}

/* RFC 8446 4.2.1 / D.1: a selected version other than 0x0304 MUST be
 * rejected (protocol_version). */
static void test_server_hello_rejects_non_tls13_version(void) {
  u8              pub[32] = {0}, got[32], buf[256];
  serverhello_out sh;
  usz             w = build_sh(buf, sizeof(buf), pub);
  buf[49]           = 0x03; /* selected version 0x0303 */
  CHECK(tls_parse_server_hello(wired_span_of(buf, w), got, &sh) == 0);
}

/* RFC 8446 4.1.3: ServerHello.legacy_version MUST be 0x0303. */
static void test_server_hello_rejects_bad_legacy_version(void) {
  u8              pub[32] = {0}, got[32], buf[256];
  serverhello_out sh;
  usz             w = build_sh(buf, sizeof(buf), pub);
  buf[5]            = 0x02; /* legacy_version 0x0302 */
  CHECK(tls_parse_server_hello(wired_span_of(buf, w), got, &sh) == 0);
}

/* RFC 8446 4.1.3: the last 8 bytes of random carrying the downgrade
 * sentinel ("DOWNGRD" || 0x01 for TLS 1.2, || 0x00 below) MUST abort. */
static void test_server_hello_rejects_downgrade_sentinel(void) {
  static const u8 sentinel[8] = {0x44, 0x4f, 0x57, 0x4e,
                                 0x47, 0x52, 0x44, 0x01};
  u8              pub[32]     = {0}, got[32], buf[256];
  serverhello_out sh;
  usz             w = build_sh(buf, sizeof(buf), pub);
  for (usz i = 0; i < 8; i++) buf[6 + 24 + i] = sentinel[i];
  CHECK(tls_parse_server_hello(wired_span_of(buf, w), got, &sh) == 0);
  buf[6 + 24 + 7] = 0x00; /* TLS 1.1-and-below sentinel */
  CHECK(tls_parse_server_hello(wired_span_of(buf, w), got, &sh) == 0);
  buf[6 + 24 + 7] = 0x02; /* not a sentinel: parse succeeds again */
  CHECK(tls_parse_server_hello(wired_span_of(buf, w), got, &sh) == 1);
}

void test_serverhello(void) {
  test_server_hello_roundtrip();
  test_server_hello_wrong_type();
  test_server_hello_truncated();
  test_server_hello_rejects_missing_supported_versions();
  test_server_hello_rejects_non_tls13_version();
  test_server_hello_rejects_bad_legacy_version();
  test_server_hello_rejects_downgrade_sentinel();
}
