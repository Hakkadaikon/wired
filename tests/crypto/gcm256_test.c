#include "test.h"

/* Parse hex of arbitrary even length into out; returns byte count.
 * Prefixed gcm256_hb (hex bytes) to avoid colliding with gcm_test.c's
 * `unhex`, which the unity build links into the same translation unit. */
static usz gcm256_hb(const char* hex, u8* out) {
  usz i = 0;
  while (hex[i * 2] != 0) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    i++;
  }
  return i;
}

/* Known-answer test: key = the AES-128 test key (feffe9...308) repeated
 * twice into a 32-byte AES-256 key; nonce/plaintext/AAD are the same NIST
 * SP 800-38D Test Case 4 inputs gcm_test.c uses for AES-128-GCM. Expected
 * ciphertext/tag were computed independently with Python's `cryptography`
 * AESGCM (AES-256, 96-bit nonce, 128-bit tag per NIST SP 800-38D) and the
 * round trip (encrypt then decrypt back to the same plaintext) was verified
 * there before transcription. */
static void test_gcm256_kat(void) {
  u8          key[32], iv[12], pt[64], aad[32], want_ct[64], want_tag[16];
  u8          ct[64 + 16]; /* ciphertext || tag */
  quic_aes256 a;
  u8          ivbuf[16];
  gcm256_hb(
      "feffe9928665731c6d6a8f9467308308"
      "feffe9928665731c6d6a8f9467308308",
      key);
  gcm256_hb("cafebabefacedbaddecaf888", ivbuf);
  for (usz i = 0; i < 12; i++) iv[i] = ivbuf[i];
  usz pl = gcm256_hb(
      "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d"
      "8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657"
      "ba637b39",
      pt);
  usz al = gcm256_hb("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad);
  gcm256_hb(
      "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08"
      "e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
      want_ct);
  gcm256_hb("76fc6ece0f4e1768cddf8853bb2d551b", want_tag);

  quic_aes256_init(&a, key);
  quic_gcm256_ctx g = {&a, iv, {aad, al}};
  quic_gcm256_seal(&g, quic_span_of(pt, pl), ct);
  for (usz i = 0; i < pl; i++) CHECK(ct[i] == want_ct[i]);
  for (usz i = 0; i < 16; i++) CHECK(ct[pl + i] == want_tag[i]);
}

/* Round-trip plus tamper detection (AUTH_FAIL leaves pt untouched). */
static void test_gcm256_open(void) {
  u8          key[32] = {0}, iv[12] = {0};
  u8          pt[20], ct[36], dec[20]; /* ct = ciphertext || tag */
  quic_aes256 a;
  for (usz i = 0; i < 20; i++) {
    pt[i]  = (u8)i;
    dec[i] = 0xCC;
  }
  quic_aes256_init(&a, key);
  quic_gcm256_ctx g = {&a, iv, {(const u8*)"hdr", 3}};
  quic_gcm256_seal(&g, quic_span_of(pt, 20), ct);

  CHECK(quic_gcm256_open(&g, quic_span_of(ct, 36), dec) == 1);
  for (usz i = 0; i < 20; i++) CHECK(dec[i] == pt[i]);

  /* flip one tag bit: must reject and not overwrite dec */
  for (usz i = 0; i < 20; i++) dec[i] = 0xCC;
  u8 bad[36];
  for (usz i = 0; i < 36; i++) bad[i] = ct[i];
  bad[20] ^= 1;
  CHECK(quic_gcm256_open(&g, quic_span_of(bad, 36), dec) == 0);
  for (usz i = 0; i < 20; i++) CHECK(dec[i] == 0xCC);

  /* flip one AAD byte: must reject */
  quic_gcm256_ctx g2 = {&a, iv, {(const u8*)"HDR", 3}};
  CHECK(quic_gcm256_open(&g2, quic_span_of(ct, 36), dec) == 0);
}

/* AES-128-GCM and AES-256-GCM keyed with the same 128-bit prefix bytes must
 * diverge: proves quic_gcm256_* is not silently falling back to the AES-128
 * path (the two ctx/seal/open pairs are genuinely independent). */
static void test_gcm256_differs_from_gcm128(void) {
  u8          key128[16] = {0}, key256[32] = {0}, iv[12] = {0};
  u8          pt[16] = {0};
  u8          ct128[16 + 16], ct256[16 + 16];
  quic_aes128 a128;
  quic_aes256 a256;

  quic_aes128_init(&a128, key128);
  quic_gcm_ctx g128 = {&a128, iv, {0, 0}};
  quic_gcm_seal(&g128, quic_span_of(pt, 16), ct128);

  quic_aes256_init(&a256, key256);
  quic_gcm256_ctx g256 = {&a256, iv, {0, 0}};
  quic_gcm256_seal(&g256, quic_span_of(pt, 16), ct256);

  int same = 1;
  for (usz i = 0; i < 16 + 16; i++)
    if (ct128[i] != ct256[i]) same = 0;
  CHECK(same == 0);
}

void test_gcm256(void) {
  test_gcm256_kat();
  test_gcm256_open();
  test_gcm256_differs_from_gcm128();
}
