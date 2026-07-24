#include "test.h"

/* digest_eq is defined in sha256_test.c, included before this file. */

/* RFC 4231 HMAC-SHA-256 test vectors. */
static void test_hmac_vectors(void) {
  u8 mac[QUIC_SHA256_DIGEST];
  u8 key1[20];
  for (usz i = 0; i < 20; i++) key1[i] = 0x0b;
  quic_hmac_sha256(
      quic_span_of(key1, 20), quic_span_of((const u8*)"Hi There", 8), mac);
  CHECK(digest_eq(
      mac, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

  quic_hmac_sha256(
      quic_span_of((const u8*)"Jefe", 4),
      quic_span_of((const u8*)"what do ya want for nothing?", 28), mac);
  CHECK(digest_eq(
      mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

/* A key longer than the block size is hashed first (RFC 4231 case 6). */
static void test_hmac_long_key(void) {
  u8 key[131], mac[QUIC_SHA256_DIGEST];
  for (usz i = 0; i < 131; i++) key[i] = 0xaa;
  quic_hmac_sha256(
      quic_span_of(key, 131),
      quic_span_of(
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
    quic_span key, quic_span msg, const u8 full[QUIC_SHA256_DIGEST]) {
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
  quic_span key = quic_span_of(key1, 20);
  quic_span msg = quic_span_of((const u8*)"Hi There", 8);

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

void test_hmac(void) {
  test_hmac_vectors();
  test_hmac_long_key();
  test_hmac_truncated();
}
