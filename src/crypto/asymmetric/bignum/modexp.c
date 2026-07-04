#include "crypto/asymmetric/bignum/modexp.h"

/* a += b, returns the carry out of the top limb. */
static u64 bn_add(quic_bn* a, const quic_bn* b) {
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
static void bn_sub(quic_bn* a, const quic_bn* b) {
  u64 borrow = 0;
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) {
    u64 d   = a->v[i] - b->v[i];
    u64 b1  = a->v[i] < b->v[i];
    a->v[i] = d - borrow;
    borrow  = b1 | (d < borrow);
  }
}

/* a <<= 1, returns the bit shifted out of the top. */
static u64 bn_shl1(quic_bn* a) {
  u64 carry = 0;
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) {
    u64 top = a->v[i] >> 63;
    a->v[i] = (a->v[i] << 1) | carry;
    carry   = top;
  }
  return carry;
}

/* True when an overflow bit or a>=m means one modulus must be subtracted. */
static int need_reduce(u64 over, const quic_bn* a, const quic_bn* m) {
  if (over) return 1;
  return quic_bn_cmp(a, m) >= 0;
}

/* Subtract one modulus from r when over or r>=m. */
static void reduce_once(quic_bn* r, u64 over, const quic_bn* m) {
  if (need_reduce(over, r, m)) bn_sub(r, m);
}

/* Multiplicand and modulus of one modular multiply. */
typedef struct {
  const quic_bn* a;
  const quic_bn* m;
} bn_mulctx;

/* r = (2*r + add_a*a) mod m, the per-bit step of double-and-add. */
static void mul_step(quic_bn* r, int add_a, bn_mulctx c) {
  reduce_once(r, bn_shl1(r), c.m);
  if (add_a) reduce_once(r, bn_add(r, c.a), c.m);
}

/* bit i (0 = LSB) of x. */
static int bn_bit(const quic_bn* x, usz i) {
  return (int)((x->v[i >> 6] >> (i & 63)) & 1);
}

/* Index of the top nonzero limb + 1, or 0 for zero. */
static usz bn_top_limb(const quic_bn* x) {
  usz i = QUIC_BN_LIMBS;
  while (i > 0 && x->v[i - 1] == 0) i--;
  return i;
}

/* Significant bits in a nonzero limb (1..64). */
static usz bn_limb_bits(u64 v) {
  usz n = 64;
  while ((v & 0x8000000000000000ULL) == 0) {
    v <<= 1;
    n--;
  }
  return n;
}

/* Significant bits in x (0 for zero). Exponent and operands here are public
 * (signature verification), so sizing the loops by the actual bit length
 * leaks nothing and avoids walking thousands of leading zero bits. */
static usz bn_bits(const quic_bn* x) {
  usz i = bn_top_limb(x);
  if (i == 0) return 0;
  return (i - 1) * 64 + bn_limb_bits(x->v[i - 1]);
}

/* r = (a * b) mod m, with a,b < m. Division-free (double-and-add). */
static void modmul(quic_bn* r, const quic_bn* b, bn_mulctx c) {
  quic_bn acc = {{0}};
  for (usz i = bn_bits(b); i > 0; i--) mul_step(&acc, bn_bit(b, i - 1), c);
  *r = acc;
}

void quic_bn_modexp(quic_bn* out, const quic_bn* base, quic_bn_expmod em) {
  quic_bn   result = {{0}};
  bn_mulctx c      = {&result, em.mod};
  result.v[0]      = 1; /* 1 mod m, m>1 */
  for (usz i = bn_bits(em.exp); i > 0; i--) {
    modmul(&result, &result, c); /* square */
    if (bn_bit(em.exp, i - 1)) modmul(&result, base, c);
  }
  *out = result;
}
