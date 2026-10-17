#include "crypto/symmetric/aead/gcm/gcm_impl.h"

/* Build H = E(K, 0^128) and J0 = nonce || 0x00000001. */
void gcm_setup(const gcm_ctx* g, gcm_st* st) {
  u8 zero[16];
  st->g = g;
  for (usz i = 0; i < 16; i++) zero[i] = 0;
  aes128_encrypt(g->aes, zero, st->h);
  for (usz i = 0; i < 12; i++) st->j0[i] = g->nonce[i];
  st->j0[12] = 0;
  st->j0[13] = 0;
  st->j0[14] = 0;
  st->j0[15] = 1;
}
