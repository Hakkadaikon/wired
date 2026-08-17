#include "test.h"

/* digest_eq is defined in sha256_test.c, included before this file. */

/* RFC 4231 HMAC-SHA-256 test vectors. */
static void test_hmac_vectors(void) {
  u8 mac[QUIC_SHA256_DIGEST];
  u8 key1[20];
  for (usz i = 0; i < 20; i++) key1[i] = 0x0b;
  quic_hmac_sha256(
      wired_span_of(key1, 20), wired_span_of((const u8*)"Hi There", 8), mac);
  CHECK(digest_eq(
      mac, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

  quic_hmac_sha256(
      wired_span_of((const u8*)"Jefe", 4),
      wired_span_of((const u8*)"what do ya want for nothing?", 28), mac);
  CHECK(digest_eq(
      mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

/* A key longer than the block size is hashed first (RFC 4231 case 6). */
static void test_hmac_long_key(void) {
  u8 key[131], mac[QUIC_SHA256_DIGEST];
  for (usz i = 0; i < 131; i++) key[i] = 0xaa;
  quic_hmac_sha256(
      wired_span_of(key, 131),
      wired_span_of(
          (const u8*)"Test Using Larger Than Block-Size Key - Hash Key First",
          54),
      mac);
  CHECK(digest_eq(
      mac, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
}

/* FIPS 198-1 5, "Truncation of HMAC Output": MAC = leftmost Tlen bytes of
 * HMAC(K, text). Re-uses the RFC 4231 case-1 vector above; the truncated
 * output must equal the corresponding prefix of the full 32-byte MAC for
 * every Tlen, and must not touch bytes past Tlen. */
/* Tlen = 16: FIPS 198-1 recommends Tlen >= 32 bits (4 bytes) and, for this
 * L=256 hash, Tlen in {16,20,24,28,32}; 16 exercises a real cut. Also checks
 * that the byte just past Tlen is left untouched. */
static void check_hmac_truncated_16(
    wired_span key, wired_span msg, const u8 full[QUIC_SHA256_DIGEST]) {
  u8 sentinel = 0xa5;
  u8 out16[17];
  for (usz i = 0; i < 17; i++) out16[i] = sentinel;
  quic_hmac_sha256_truncated(key, msg, out16, 16);
  for (usz i = 0; i < 16; i++) CHECK(out16[i] == full[i]);
  CHECK(out16[16] == sentinel); /* byte 17 untouched */
}

static void test_hmac_truncated(void) {
  u8 key1[20];
  for (usz i = 0; i < 20; i++) key1[i] = 0x0b;
  wired_span key = wired_span_of(key1, 20);
  wired_span msg = wired_span_of((const u8*)"Hi There", 8);

  u8 full[QUIC_SHA256_DIGEST];
  quic_hmac_sha256(key, msg, full);

  check_hmac_truncated_16(key, msg, full);

  /* Tlen = 32 (no truncation) must reproduce the full MAC exactly. */
  u8 out32[QUIC_SHA256_DIGEST];
  quic_hmac_sha256_truncated(key, msg, out32, QUIC_SHA256_DIGEST);
  for (usz i = 0; i < QUIC_SHA256_DIGEST; i++) CHECK(out32[i] == full[i]);

  /* Tlen = 0 writes nothing. */
  u8 out0 = 0xa5;
  quic_hmac_sha256_truncated(key, msg, &out0, 0);
  CHECK(out0 == 0xa5);
}

/* Compare a 48-byte HMAC-SHA-384 MAC against its expected bytes. */
static int hmac384_eq(const u8 got[QUIC_SHA384_DIGEST], const u8* want) {
  usz diff = 0;
  for (usz i = 0; i < QUIC_SHA384_DIGEST; i++) diff |= (usz)(got[i] ^ want[i]);
  return diff == 0;
}

/* RFC 4231 Test Case 1/2, HMAC-SHA-384 vectors. Values re-derived with
 * Python's hmac.new(key, msg, hashlib.sha384).hexdigest(). */
static void test_hmac384_vectors(void) {
  static const u8 want1[QUIC_SHA384_DIGEST] = {
      0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4,
      0xab, 0x46, 0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
      0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9,
      0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6};
  static const u8 want2[QUIC_SHA384_DIGEST] = {
      0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31, 0x61, 0x7f, 0x78, 0xd2,
      0xb5, 0x8a, 0x6b, 0x1b, 0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47,
      0xe4, 0x2e, 0xc3, 0x73, 0x63, 0x22, 0x44, 0x5e, 0x8e, 0x22, 0x40, 0xca,
      0x5e, 0x69, 0xe2, 0xc7, 0x8b, 0x32, 0x39, 0xec, 0xfa, 0xb2, 0x16, 0x49};
  u8 mac[QUIC_SHA384_DIGEST];
  u8 key1[20];
  for (usz i = 0; i < 20; i++) key1[i] = 0x0b;
  quic_hmac_sha384(
      wired_span_of(key1, 20), wired_span_of((const u8*)"Hi There", 8), mac);
  CHECK(hmac384_eq(mac, want1));

  quic_hmac_sha384(
      wired_span_of((const u8*)"Jefe", 4),
      wired_span_of((const u8*)"what do ya want for nothing?", 28), mac);
  CHECK(hmac384_eq(mac, want2));
}

/* RFC 4231 Test Case 6: a key longer than the 128-byte block is hashed
 * first. Value re-derived with Python hmac/hashlib as above. */
static void test_hmac384_long_key(void) {
  static const u8 want[QUIC_SHA384_DIGEST] = {
      0x4e, 0xce, 0x08, 0x44, 0x85, 0x81, 0x3e, 0x90, 0x88, 0xd2, 0xc6, 0x3a,
      0x04, 0x1b, 0xc5, 0xb4, 0x4f, 0x9e, 0xf1, 0x01, 0x2a, 0x2b, 0x58, 0x8f,
      0x3c, 0xd1, 0x1f, 0x05, 0x03, 0x3a, 0xc4, 0xc6, 0x0c, 0x2e, 0xf6, 0xab,
      0x40, 0x30, 0xfe, 0x82, 0x96, 0x24, 0x8d, 0xf1, 0x63, 0xf4, 0x49, 0x52};
  u8 key[131], mac[QUIC_SHA384_DIGEST];
  for (usz i = 0; i < 131; i++) key[i] = 0xaa;
  quic_hmac_sha384(
      wired_span_of(key, 131),
      wired_span_of(
          (const u8*)"Test Using Larger Than Block-Size Key - Hash Key First",
          54),
      mac);
  CHECK(hmac384_eq(mac, want));
}

void test_hmac(void) {
  test_hmac_vectors();
  test_hmac_long_key();
  test_hmac_truncated();
  test_hmac384_vectors();
  test_hmac384_long_key();
}
