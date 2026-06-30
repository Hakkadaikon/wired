#include "transport/packet/protect/hp/hp_chacha.h"

#include "crypto/symmetric/aead/chacha/chacha20.h"

void quic_hp_chacha_mask(const u8 hp_key[32], const u8 sample[16], u8 mask[5]) {
  /* RFC 9001 5.4.2 */
  u32 counter = (u32)sample[0] | ((u32)sample[1] << 8) |
                ((u32)sample[2] << 16) | ((u32)sample[3] << 24);
  u8 block[QUIC_CHACHA_BLOCK];
  quic_chacha20_block(hp_key, counter, sample + 4, block);
  for (usz i = 0; i < 5; i++) mask[i] = block[i];
}
