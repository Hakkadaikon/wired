#ifndef CRYPTO_SYMMETRIC_AEAD_CHACHA_POLY1305_IMPL_H
#define CRYPTO_SYMMETRIC_AEAD_CHACHA_POLY1305_IMPL_H

#include "crypto/symmetric/aead/chacha/poly1305_impl_head.h"

static inline u32 poly1305_rd32le(const u8* p) {
  return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* Absorb full 16-byte blocks (hibit set), one partial block padded with a 1. */
static inline void poly_blocks(poly* st, const u8* msg, usz len) {
  usz off = 0;
  while (len - off >= 16) {
    poly_add(st, msg + off, 1 << 24);
    poly_mulmod(st);
    off += 16;
  }
  if (off < len) {
    poly_final_block(st, msg + off, len - off);
  }
}

#endif
