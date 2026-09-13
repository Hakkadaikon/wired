#include "test.h"

static void test_aead_suite_nonce(void);

void test_aead_suite(void) {
  u8 key[32], iv[12], aad[7], pt[20], ct[40], out[20];
  for (usz i = 0; i < 32; i++) key[i] = (u8)(0x40 + i);
  for (usz i = 0; i < 12; i++) iv[i] = (u8)(0x10 + i);
  for (usz i = 0; i < 7; i++) aad[i] = (u8)(0xa0 + i);
  for (usz i = 0; i < 20; i++) pt[i] = (u8)i;

  /* RFC 9001 5.3 AES suite: matches the fixed GCM pipeline directly. */
  aead_suite_op aes = {
      TLS_AES_128_GCM_SHA256, key, iv, 2, wired_span_of(aad, 7)};
  usz n = aead_suite_seal(&aes, wired_span_of(pt, 20), ct);
  CHECK(n == 20 + 16);
  aes128 a;
  aes128_init(&a, key);
  u8 nonce[12], want[36]; /* ciphertext || tag */
  for (usz i = 0; i < 12; i++) nonce[i] = iv[i];
  nonce[11] ^= 2;
  gcm_ctx g = {&a, nonce, {aad, 7}};
  gcm_seal(&g, wired_span_of(pt, 20), want);
  for (usz i = 0; i < 36; i++) CHECK(ct[i] == want[i]);

  /* AES seal -> open round-trips. */
  CHECK(aead_suite_open(&aes, wired_span_of(ct, 20), out) == 20);
  for (usz i = 0; i < 20; i++) CHECK(out[i] == pt[i]);

  /* RFC 9001 5.3 ChaCha suite: seal -> open round-trips. */
  aead_suite_op cha = {
      TLS_CHACHA20_POLY1305_SHA256, key, iv, 5, wired_span_of(aad, 7)};
  n = aead_suite_seal(&cha, wired_span_of(pt, 20), ct);
  CHECK(n == 20 + 16);
  CHECK(aead_suite_open(&cha, wired_span_of(ct, 20), out) == 20);
  for (usz i = 0; i < 20; i++) CHECK(out[i] == pt[i]);

  /* Tampered tag fails authentication. */
  ct[20] ^= 0xff;
  CHECK(aead_suite_open(&cha, wired_span_of(ct, 20), out) == 0);

  /* Unknown suite seals/opens nothing. */
  aead_suite_op bad = {0x0000, key, iv, 2, wired_span_of(aad, 7)};
  CHECK(aead_suite_seal(&bad, wired_span_of(pt, 20), ct) == 0);
  CHECK(aead_suite_open(&bad, wired_span_of(ct, 20), out) == 0);

  test_aead_suite_nonce();
}

/* Pinning: RFC 9001 5.3 nonce = iv XOR pn. Two different packet numbers
 * under the same key/iv must derive two different nonces, so ciphertext for
 * the same plaintext differs and a ciphertext sealed under one pn does not
 * open under another (V-0764). */
static void test_aead_suite_nonce(void) {
  u8 key[32], iv[12], pt[16], ct1[32], ct2[32], out[16];
  for (usz i = 0; i < 32; i++) key[i] = (u8)(0x20 + i);
  for (usz i = 0; i < 12; i++) iv[i] = (u8)(0x03 + i);
  for (usz i = 0; i < 16; i++) pt[i] = (u8)(0x55 + i);

  aead_suite_op op1 = {
      TLS_AES_128_GCM_SHA256, key, iv, 1, wired_span_of((const u8*)"h", 1)};
  aead_suite_op op2 = {
      TLS_AES_128_GCM_SHA256, key, iv, 2, wired_span_of((const u8*)"h", 1)};

  CHECK(aead_suite_seal(&op1, wired_span_of(pt, 16), ct1) == 32);
  CHECK(aead_suite_seal(&op2, wired_span_of(pt, 16), ct2) == 32);

  int differ = 0;
  for (usz i = 0; i < 32; i++) differ |= (ct1[i] != ct2[i]);
  CHECK(differ);

  /* ciphertext sealed under pn=1 must not open under pn=2's nonce. */
  CHECK(aead_suite_open(&op2, wired_span_of(ct1, 16), out) == 0);
}
