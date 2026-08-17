#include "test.h"

void test_aead_suite(void) {
  u8 key[32], iv[12], aad[7], pt[20], ct[40], out[20];
  for (usz i = 0; i < 32; i++) key[i] = (u8)(0x40 + i);
  for (usz i = 0; i < 12; i++) iv[i] = (u8)(0x10 + i);
  for (usz i = 0; i < 7; i++) aad[i] = (u8)(0xa0 + i);
  for (usz i = 0; i < 20; i++) pt[i] = (u8)i;

  /* RFC 9001 5.3 AES suite: matches the fixed GCM pipeline directly. */
  aead_suite_op aes = {
      QUIC_TLS_AES_128_GCM_SHA256, key, iv, 2, wired_span_of(aad, 7)};
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
      QUIC_TLS_CHACHA20_POLY1305_SHA256, key, iv, 5, wired_span_of(aad, 7)};
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
}
