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

/* RFC 5869 has no official SHA-384 vectors (Appendix A covers only SHA-256
 * and SHA-1); these three cases mirror the shape of A.1-A.3 with SHA-384 and
 * were independently cross-checked with Python hashlib/hmac and the OpenSSL
 * 3.0.13 `openssl kdf HKDF` / `openssl dgst -mac HMAC` CLI before being
 * baked in here. */
static void test_hkdf384_case1(void) {
  u8 ikm[22], salt[13], info[10], prk[48], okm[42];
  for (usz i = 0; i < 22; i++) ikm[i] = 0x0b;
  for (usz i = 0; i < 13; i++) salt[i] = (u8)i;
  for (usz i = 0; i < 10; i++) info[i] = (u8)(0xf0 + i);

  quic_hkdf_extract_384(quic_span_of(salt, 13), quic_span_of(ikm, 22), prk);
  CHECK(hex_eq(
      prk,
      "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8d"
      "ec70ee9a7e1f3e293ef68eceb072a5ade",
      48));

  CHECK(quic_hkdf_expand_384(
      prk, quic_span_of(info, 10), quic_mspan_of(okm, 42)));
  CHECK(hex_eq(
      okm,
      "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f"
      "748b6457763e4f0204fc5",
      42));
}

static void test_hkdf384_case2(void) {
  u8 ikm[80], salt[80], info[80], prk[48], okm[82];
  for (usz i = 0; i < 80; i++) ikm[i] = (u8)i;
  for (usz i = 0; i < 80; i++) salt[i] = (u8)(0x60 + i);
  for (usz i = 0; i < 80; i++) info[i] = (u8)(0xb0 + i);

  quic_hkdf_extract_384(quic_span_of(salt, 80), quic_span_of(ikm, 80), prk);
  CHECK(hex_eq(
      prk,
      "b319f6831dff9314efb643baa29263b30e4a8d779fe31e9c901efd7de737c85"
      "b62e676d4dc87b0895c6a7dc97b52cebb",
      48));

  CHECK(quic_hkdf_expand_384(
      prk, quic_span_of(info, 80), quic_mspan_of(okm, 82)));
  CHECK(hex_eq(
      okm,
      "484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649ee"
      "bf69f8d5c832856bf4e4fbc17967d54975324a94987f7f41835817d8994fdbd"
      "6f4c09c5500dca24a56222fea53d8967a8b2e",
      82));
}

static void test_hkdf384_case3(void) {
  u8 ikm[22], prk[48], okm[42];
  for (usz i = 0; i < 22; i++) ikm[i] = 0x0b;

  quic_hkdf_extract_384(quic_span_of(0, 0), quic_span_of(ikm, 22), prk);
  CHECK(hex_eq(
      prk,
      "10e40cf072a4c5626e43dd22c1cf727d4bb140975c9ad0cbc8e45b40068f8f0b"
      "a57cdb598af9dfa6963a96899af047e5",
      48));

  CHECK(quic_hkdf_expand_384(prk, quic_span_of(0, 0), quic_mspan_of(okm, 42)));
  CHECK(hex_eq(
      okm,
      "c8c96e710f89b0d7990bca68bcdec8cf854062e54c73a7abc743fade9b242da"
      "acc1cea5670415b52849c",
      42));
}

/* RFC 5869 2.3: L MUST be <= 255*HashLen. HashLen == 48 for SHA-384, so
 * 255*48 == 12240 is the last valid length and 12241 must be rejected. */
static void test_hkdf384_expand_length_too_large(void) {
  static u8 okm[12240];
  u8        prk[48] = {0};
  CHECK(
      quic_hkdf_expand_384(
          prk, quic_span_of(0, 0), quic_mspan_of(okm, 12240)) == 1);
  CHECK(
      quic_hkdf_expand_384(
          prk, quic_span_of(0, 0), quic_mspan_of(okm, 12241)) == 0);
}

/* Expand-Label wraps Expand with the tls13 label struct; check it produces
 * a stable, correctly-sized output and that different labels diverge. */
static void test_hkdf384_expand_label(void) {
  u8              prk[48], a[16], b[16];
  quic_hkdf_label lk = {"quic key", 8, {0, 0}};
  quic_hkdf_label li = {"quic iv", 7, {0, 0}};
  for (usz i = 0; i < 48; i++) prk[i] = (u8)i;
  CHECK(quic_hkdf_expand_label_384(prk, &lk, quic_mspan_of(a, 16)));
  CHECK(quic_hkdf_expand_label_384(prk, &lk, quic_mspan_of(b, 16)));
  for (usz i = 0; i < 16; i++) CHECK(a[i] == b[i]); /* deterministic */
  CHECK(quic_hkdf_expand_label_384(prk, &li, quic_mspan_of(b, 16)));
  int differ = 0;
  for (usz i = 0; i < 16; i++) differ |= (a[i] != b[i]);
  CHECK(differ);
}

void test_hkdf(void) {
  test_hkdf_rfc5869();
  test_hkdf_expand_label();
  test_hkdf_expand_length_too_large();
  test_hkdf_rfc5869_case2();
  test_hkdf_rfc5869_case3();
  test_hkdf384_case1();
  test_hkdf384_case2();
  test_hkdf384_case3();
  test_hkdf384_expand_length_too_large();
  test_hkdf384_expand_label();
}
