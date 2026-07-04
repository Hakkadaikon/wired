#include "crypto/asymmetric/bignum/bignum.h"

static void bn_zero(quic_bn* a) {
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) a->v[i] = 0;
}

void quic_bn_from_be(quic_bn* out, const u8* be, usz len) {
  bn_zero(out);
  /* last byte of be is the least significant; pack 8 per limb. */
  for (usz i = 0; i < len; i++) {
    usz pos = len - 1 - i; /* byte index, 0 = least significant */
    out->v[i >> 3] |= (u64)be[pos] << ((i & 7) * 8);
  }
}

void quic_bn_to_be(const quic_bn* a, u8* be, usz len) {
  for (usz i = 0; i < len; i++) {
    usz from_lsb = len - 1 - i; /* how far this byte is from the LSB */
    u64 limb     = a->v[from_lsb >> 3];
    be[i]        = (u8)(limb >> ((from_lsb & 7) * 8));
  }
}

/* -1/0/1 for a single limb pair. */
static int limb_cmp(u64 x, u64 y) {
  if (x < y) return -1;
  return x > y ? 1 : 0;
}

int quic_bn_cmp(const quic_bn* a, const quic_bn* b) {
  for (usz k = QUIC_BN_LIMBS; k > 0; k--) {
    int c = limb_cmp(a->v[k - 1], b->v[k - 1]);
    if (c) return c;
  }
  return 0;
}

int quic_bn_is_zero(const quic_bn* a) {
  u64 acc = 0;
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) acc |= a->v[i];
  return acc == 0;
}
