#include "test.h"

/* hex_eq compares len bytes of got against a hex string. */
static int hex_eq(const u8* got, const char* hex, usz len) {
  for (usz i = 0; i < len; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    u8 b = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    if (got[i] != b) return 0;
  }
  return 1;
}

/* RFC 5869 Appendix A.1 (SHA-256). */
static void test_hkdf_rfc5869(void) {
  u8 ikm[22], salt[13], info[10], prk[32], okm[42];
  for (usz i = 0; i < 22; i++) ikm[i] = 0x0b;
  for (usz i = 0; i < 13; i++) salt[i] = (u8)i;
  for (usz i = 0; i < 10; i++) info[i] = (u8)(0xf0 + i);

  quic_hkdf_extract(quic_span_of(salt, 13), quic_span_of(ikm, 22), prk);
  CHECK(hex_eq(
      prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
      32));

  CHECK(quic_hkdf_expand(prk, quic_span_of(info, 10), quic_mspan_of(okm, 42)));
  CHECK(hex_eq(
      okm,
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
      "34007208d5b887185865",
      42));
}

/* Expand-Label wraps Expand with the tls13 label struct; check it produces
 * a stable, correctly-sized output (exercised end-to-end by the QUIC
 * Initial vectors later). */
static void test_hkdf_expand_label(void) {
  u8              prk[32], a[16], b[16];
  quic_hkdf_label lk = {"quic key", 8, {0, 0}};
  quic_hkdf_label li = {"quic iv", 7, {0, 0}};
  for (usz i = 0; i < 32; i++) prk[i] = (u8)i;
  CHECK(quic_hkdf_expand_label(prk, &lk, quic_mspan_of(a, 16)));
  CHECK(quic_hkdf_expand_label(prk, &lk, quic_mspan_of(b, 16)));
  for (usz i = 0; i < 16; i++) CHECK(a[i] == b[i]); /* deterministic */
  /* a different label gives different output */
  CHECK(quic_hkdf_expand_label(prk, &li, quic_mspan_of(b, 16)));
  int differ = 0;
  for (usz i = 0; i < 16; i++) differ |= (a[i] != b[i]);
  CHECK(differ);
}

/* RFC 5869 2.3: L (the requested output length) MUST be <= 255*HashLen.
 * HashLen == 32 for SHA-256, so 255*32 == 8160 is the last valid length and
 * 8161 must be rejected. On the reject path expand_ok returns 0 before any
 * write, so the 8161 case is checked against a real 8160-byte buffer too
 * (reused, never actually written past its size on that call). */
static void test_hkdf_expand_length_too_large(void) {
  static u8 okm[8160];
  u8        prk[32] = {0};
  CHECK(
      quic_hkdf_expand(prk, quic_span_of(0, 0), quic_mspan_of(okm, 8160)) == 1);
  CHECK(
      quic_hkdf_expand(prk, quic_span_of(0, 0), quic_mspan_of(okm, 8161)) == 0);
}

/* RFC 5869 Appendix A.2: SHA-256, L=82, 80-octet IKM/salt/info (values re-
 * derived independently from a from-scratch SHA-256/HMAC implementation
 * before being baked in here, per the RFC's own test vector). */
static void test_hkdf_rfc5869_case2(void) {
  u8 ikm[80], salt[80], info[80], prk[32], okm[82];
  for (usz i = 0; i < 80; i++) ikm[i] = (u8)i;
  for (usz i = 0; i < 80; i++) salt[i] = (u8)(0x60 + i);
  for (usz i = 0; i < 80; i++) info[i] = (u8)(0xb0 + i);

  quic_hkdf_extract(quic_span_of(salt, 80), quic_span_of(ikm, 80), prk);
  CHECK(hex_eq(
      prk, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
      32));

  CHECK(quic_hkdf_expand(prk, quic_span_of(info, 80), quic_mspan_of(okm, 82)));
  CHECK(hex_eq(
      okm,
      "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c5"
      "9045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc"
      "30c58179ec3e87c14c01d5c1f3434f1d87",
      82));
}

/* RFC 5869 Appendix A.3: SHA-256, zero-length salt and info, L=42. */
static void test_hkdf_rfc5869_case3(void) {
  u8 ikm[22], prk[32], okm[42];
  for (usz i = 0; i < 22; i++) ikm[i] = 0x0b;

  quic_hkdf_extract(quic_span_of(0, 0), quic_span_of(ikm, 22), prk);
  CHECK(hex_eq(
      prk, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
      32));

  CHECK(quic_hkdf_expand(prk, quic_span_of(0, 0), quic_mspan_of(okm, 42)));
  CHECK(hex_eq(
      okm,
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d"
      "201395faa4b61a96c8",
      42));
}

void test_hkdf(void) {
  test_hkdf_rfc5869();
  test_hkdf_expand_label();
  test_hkdf_expand_length_too_large();
  test_hkdf_rfc5869_case2();
  test_hkdf_rfc5869_case3();
}
