#include "test.h"

static void hps_uhx(const char* hex, u8* out, usz n) {
  for (usz i = 0; i < n; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

void test_hp_suite(void) {
  u8 sample[16], mask[5];

  /* RFC 9001 5.4.3 AES suite: same mask as the AES-ECB path. */
  u8 aes_key[16];
  for (usz i = 0; i < 16; i++) aes_key[i] = (u8)i;
  for (usz i = 0; i < 16; i++) sample[i] = (u8)(0x10 + i);
  CHECK(
      quic_hp_suite_mask(QUIC_TLS_AES_128_GCM_SHA256, aes_key, sample, mask) ==
      1);
  quic_aes128 hp;
  quic_aes128_init(&hp, aes_key);
  u8 want_aes[5];
  quic_hp_mask(&hp, sample, want_aes);
  for (usz i = 0; i < 5; i++) CHECK(mask[i] == want_aes[i]);

  /* RFC 9001 5.4.4 ChaCha suite: A.5 vector. */
  u8 cha_key[32];
  hps_uhx(
      "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
      cha_key, 32);
  hps_uhx("5e5cd55c41f69080575d7999c25a5bfb", sample, 16);
  CHECK(
      quic_hp_suite_mask(
          QUIC_TLS_CHACHA20_POLY1305_SHA256, cha_key, sample, mask) == 1);
  u8 want_cha[5];
  hps_uhx("aefefe7d03", want_cha, 5);
  for (usz i = 0; i < 5; i++) CHECK(mask[i] == want_cha[i]);

  /* Unknown suite: no derivation. */
  CHECK(quic_hp_suite_mask(0x0000, cha_key, sample, mask) == 0);
}
