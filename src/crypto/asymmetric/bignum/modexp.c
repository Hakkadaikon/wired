#include "crypto/asymmetric/bignum/modexp.h"

/* a += b, returns the carry out of the top limb. */
static u64 bn_add(quic_bn *a, const quic_bn *b) {
  u64 c = 0;
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) {
    u64 s   = a->v[i] + b->v[i];
    u64 c1  = s < a->v[i];
    a->v[i] = s + c;
    c       = c1 | (a->v[i] < c);
  }
  return c;
}

/* a -= b, assumes a >= b. */
static void bn_sub(quic_bn *a, const quic_bn *b) {
  u64 borrow = 0;
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) {
    u64 d   = a->v[i] - b->v[i];
    u64 b1  = a->v[i] < b->v[i];
    a->v[i] = d - borrow;
    borrow  = b1 | (d < borrow);
  }
}

/* a <<= 1, returns the bit shifted out of the top. */
static u64 bn_shl1(quic_bn *a) {
  u64 carry = 0;
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) {
    u64 top = a->v[i] >> 63;
    a->v[i] = (a->v[i] << 1) | carry;
    carry   = top;
  }
  return carry;
}

/* True when an overflow bit or a>=m means one modulus must be subtracted. */
static int need_reduce(u64 over, const quic_bn *a, const quic_bn *m) {
  if (over) return 1;
  return quic_bn_cmp(a, m) >= 0;
}

/* Subtract one modulus from r when over or r>=m. */
static void reduce_once(quic_bn *r, u64 over, const quic_bn *m) {
  if (need_reduce(over, r, m)) bn_sub(r, m);
}

/* r = (2*r + add_a*a) mod m, the per-bit step of double-and-add. */
static void mul_step(
    quic_bn *r, int add_a, const quic_bn *a, const quic_bn *m) {
  reduce_once(r, bn_shl1(r), m);
  if (add_a) reduce_once(r, bn_add(r, a), m);
}

/* bit i (0 = LSB) of x. */
static int bn_bit(const quic_bn *x, usz i) {
  return (int)((x->v[i >> 6] >> (i & 63)) & 1);
}

/* r = (a * b) mod m, with a,b < m. Division-free (double-and-add). */
static void modmul(
    quic_bn *r, const quic_bn *a, const quic_bn *b, const quic_bn *m) {
  quic_bn acc = {{0}};
  for (usz i = (usz)QUIC_BN_LIMBS * 64; i > 0; i--)
    mul_step(&acc, bn_bit(b, i - 1), a, m);
  *r = acc;
}

void quic_bn_modexp(
    quic_bn *out, const quic_bn *base, const quic_bn *exp, const quic_bn *mod) {
  quic_bn result = {{0}};
  result.v[0]    = 1; /* 1 mod m, m>1 */
  for (usz i = (usz)QUIC_BN_LIMBS * 64; i > 0; i--) {
    modmul(&result, &result, &result, mod);
    if (bn_bit(exp, i - 1)) modmul(&result, &result, base, mod);
  }
  *out = result;
}
