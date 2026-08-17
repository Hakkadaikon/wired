#include "transport/packet/protect/hp/hp.h"

void hp_mask(const aes128* hp, const u8 sample[HP_SAMPLE], u8 mask[5]) {
  u8 block[AES_BLOCK];
  aes128_encrypt(hp, sample, block);
  for (usz i = 0; i < 5; i++) mask[i] = block[i];
}

void hp_apply(const u8 mask[5], const hp_fields* f) {
  *f->byte0 ^= mask[0] & f->bits_mask;
  for (usz i = 0; i < f->pn_len; i++) f->pn[i] ^= mask[1 + i];
}
