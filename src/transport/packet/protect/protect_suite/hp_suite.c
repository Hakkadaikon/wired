#include "transport/packet/protect/protect_suite/hp_suite.h"

#include "tls/handshake/core/tls/cipher.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/hp/hp_chacha.h"

int hp_suite_mask(
    u16 suite, const u8* hp_key, const u8 sample[16], u8 mask[5]) {
  if (suite == TLS_AES_128_GCM_SHA256) {
    aes128 hp;
    aes128_init(&hp, hp_key);
    hp_mask(&hp, sample, mask);
    return 1;
  }
  if (suite == TLS_CHACHA20_POLY1305_SHA256) {
    hp_chacha_mask(hp_key, sample, mask);
    return 1;
  }
  return 0;
}
