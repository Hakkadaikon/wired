#include "test.h"

/* keq compares len bytes against a hex string. */
static int keq(const u8* got, const char* hex, usz len) {
  for (usz i = 0; i < len; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    u8 b = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    if (got[i] != b) return 0;
  }
  return 1;
}

/* Byte-exact compare (keq above compares against a hex string; this compares
 * two raw byte buffers). */
static int same_bytes(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* RFC 9001 Appendix A.1: DCID 0x8394c8f03e515708. */
static void test_initial_client(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys k;
  quic_initial_derive(quic_span_of(dcid, 8), 0, QUIC_VERSION_1, &k);
  CHECK(keq(k.key, "1f369613dd76d5467730efcbe3b1a22d", 16));
  CHECK(keq(k.iv, "fa044b2f42a3fd3b46fb255c", 12));
  CHECK(keq(k.hp, "9f50449e04a0e810283a1e9933adedd2", 16));
}

static void test_initial_server(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys k;
  quic_initial_derive(quic_span_of(dcid, 8), 1, QUIC_VERSION_1, &k);
  CHECK(keq(k.key, "cf3a5331653c364c88f0f379b6067e37", 16));
  CHECK(keq(k.iv, "0ac1493ca1905853b0bba03e", 12));
  CHECK(keq(k.hp, "c206b8d9b9f0f37644430b490eeaa314", 16));
}

/* v2 must not silently reuse the v1 salt/labels: same DCID, different
 * version, so the derived client key must differ from the v1 result. */
static void test_initial_v2_differs_from_v1(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys v2;
  quic_initial_derive(quic_span_of(dcid, 8), 0, QUIC_VERSION_2, &v2);
  CHECK(!keq(v2.key, "1f369613dd76d5467730efcbe3b1a22d", 16));
}

/* RFC 9369 Appendix A: same DCID as RFC 9001 A.1, v2 salt/labels. Values
 * independently re-derived by hand (HKDF-Extract(v2 salt, dcid) -> "client
 * in"/"quicv2 key,iv,hp") before pinning, per this repo's rule against
 * trusting a single fetched golden value unchecked. */
static void test_initial_v2_client(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys k;
  quic_initial_derive(quic_span_of(dcid, 8), 0, QUIC_VERSION_2, &k);
  CHECK(keq(k.key, "8b1a0bc121284290a29e0971b5cd045d", 16));
  CHECK(keq(k.iv, "91f73e2351d8fa91660e909f", 12));
  CHECK(keq(k.hp, "45b95e15235d6f45a6b19cbcb0294ba9", 16));
}

static void test_initial_v2_server(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys k;
  quic_initial_derive(quic_span_of(dcid, 8), 1, QUIC_VERSION_2, &k);
  CHECK(keq(k.key, "82db637861d55e1d011f19ea71d5d2a7", 16));
  CHECK(keq(k.iv, "dd13c276499c0249d3310652", 12));
  CHECK(keq(k.hp, "edf6d05c83121201b436e16877593c3a", 16));
}

/* v2's derivation must thread the pinned v2 Initial salt (v2keys_test.c's
 * V2_GOLDEN, RFC 9369 3.3.1) through HKDF-Extract: reproduce
 * client_initial_secret by hand from quic_version_initial_salt(
 * QUIC_VERSION_2, ...) plus the "client in" / "quicv2 key" labels, and
 * confirm it reproduces quic_initial_derive's key. This closes the "salt
 * one-source-of-truth" gap (R-25): if initial.c ever drifted back to a
 * locally hard-coded salt, this test would catch it even without a full
 * RFC 9369 Appendix A golden vector (that full pin is R-26). */
static void test_initial_v2_uses_pinned_salt(void) {
  const u8*         salt;
  usz               salt_len;
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  u8                secret[QUIC_HKDF_PRK], side[QUIC_HKDF_PRK];
  u8                want_key[QUIC_INITIAL_KEY];
  quic_hkdf_label   cl = {"client in", 9, {0, 0}};
  quic_hkdf_label   kl = {"quicv2 key", 10, {0, 0}};
  quic_initial_keys got;
  CHECK(quic_version_initial_salt(QUIC_VERSION_2, &salt, &salt_len) == 1);
  quic_hkdf_extract(
      quic_span_of(salt, salt_len), quic_span_of(dcid, 8), secret);
  quic_hkdf_expand_label(secret, &cl, quic_mspan_of(side, QUIC_HKDF_PRK));
  quic_hkdf_expand_label(side, &kl, quic_mspan_of(want_key, QUIC_INITIAL_KEY));
  quic_initial_derive(quic_span_of(dcid, 8), 0, QUIC_VERSION_2, &got);
  CHECK(same_bytes(got.key, want_key, QUIC_INITIAL_KEY));
}

void test_initial(void) {
  test_initial_client();
  test_initial_server();
  test_initial_v2_client();
  test_initial_v2_server();
  test_initial_v2_differs_from_v1();
  test_initial_v2_uses_pinned_salt();
}
