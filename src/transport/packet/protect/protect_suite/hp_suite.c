#include "transport/packet/protect/protect_suite/hp_suite.h"

#include "tls/handshake/core/tls/cipher.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/hp/hp_chacha.h"

/* RFC 9001 5.4.3: AES-128-ECB over the sample. */
static void hps_aes128(const u8* hp_key, const u8 sample[16], u8 mask[5]) {
  aes128 hp;
  aes128_init(&hp, hp_key);
  hp_mask(&hp, sample, mask);
}

/* RFC 9001 5.4.3: AES-256-ECB over the sample (TLS_AES_256_GCM_SHA384). */
static void hps_aes256(const u8* hp_key, const u8 sample[16], u8 mask[5]) {
  aes256 hp;
  u8     block[AES_BLOCK];
  aes256_init(&hp, hp_key);
  aes256_encrypt(&hp, sample, block);
  for (usz i = 0; i < 5; i++) mask[i] = block[i];
}

/* RFC 9001 5.4.4: ChaCha20 keystream block. */
static void hps_chacha(const u8* hp_key, const u8 sample[16], u8 mask[5]) {
  hp_chacha_mask(hp_key, sample, mask);
}

static const struct {
  u16 suite;
  void (*mask)(const u8* hp_key, const u8 sample[16], u8 mask[5]);
} hps_tab[] = {
    {TLS_AES_128_GCM_SHA256, hps_aes128},
    {TLS_AES_256_GCM_SHA384, hps_aes256},
    {TLS_CHACHA20_POLY1305_SHA256, hps_chacha},
};

int hp_suite_mask(
    u16 suite, const u8* hp_key, const u8 sample[16], u8 mask[5]) {
  for (usz i = 0; i < sizeof hps_tab / sizeof *hps_tab; i++) {
    if (hps_tab[i].suite != suite) continue;
    hps_tab[i].mask(hp_key, sample, mask);
    return 1;
  }
  return 0;
}
