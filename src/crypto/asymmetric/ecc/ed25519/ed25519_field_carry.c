#include "crypto/asymmetric/ecc/ed25519/ed25519_field_impl.h"

static void store_reduced(u8* s, const fe r);
static void carry_pass(fe r);
static void carry_pass_final(fe r);

/* Load 32 little-endian bytes into limbs (top bit of byte 31 is cleared). */
void ed_fe_frombytes(fe h, const u8* s) {
  u64 t[4];
  for (usz i = 0; i < 4; i++) {
    t[i] = 0;
    for (usz j = 0; j < 8; j++) t[i] |= (u64)s[i * 8 + j] << (8 * j);
  }
  h[0] = t[0] & MASK51;
  h[1] = ((t[0] >> 51) | (t[1] << 13)) & MASK51;
  h[2] = ((t[1] >> 38) | (t[2] << 26)) & MASK51;
  h[3] = ((t[2] >> 25) | (t[3] << 39)) & MASK51;
  h[4] = (t[3] >> 12) & MASK51;
}

/* Pack five reduced 51-bit limbs into 32 little-endian bytes. */
static void store_reduced(u8* s, const fe r) {
  u64 w[4];
  w[0] = r[0] | (r[1] << 51);
  w[1] = (r[1] >> 13) | (r[2] << 38);
  w[2] = (r[2] >> 26) | (r[3] << 25);
  w[3] = (r[3] >> 39) | (r[4] << 12);
  for (usz i = 0; i < 4; i++)
    for (usz j = 0; j < 8; j++) s[i * 8 + j] = (u8)(w[i] >> (8 * j));
}

/* One weak-carry pass: every limb < 2^51, top carry folded by 19. */
static void carry_pass(fe r) {
  u64 c = 0;
  for (usz i = 0; i < 5; i++) {
    r[i] += c;
    c = r[i] >> 51;
    r[i] &= MASK51;
  }
  r[0] += c * 19;
}

/* Final carry chain for ed_fe_tobytes: unlike carry_pass, the top limb's
 * overflow is dropped (truncation mod 2^255), not folded back with *19. At
 * this point r is already < 2^255 + 19 (q has subtracted at most one p), so
 * the top carry is 0 or the deliberate q-induced wrap that must vanish here
 * rather than re-entering the r[0] += 19*carry identity a second time. */
static void carry_pass_final(fe r) {
  u64 c = 0;
  for (usz i = 0; i < 5; i++) {
    r[i] += c;
    c = r[i] >> 51;
    r[i] &= MASK51;
  }
}

/* Fully reduce h mod p and store 32 little-endian bytes. */
void ed_fe_tobytes(u8* s, const fe h) {
  fe  r;
  u64 q;
  ed_fe_copy(r, h);
  carry_pass(r);
  carry_pass(r);
  q = (r[0] + 19) >> 51;
  for (usz i = 1; i < 5; i++) q = (r[i] + q) >> 51;
  r[0] += 19 * q;
  carry_pass_final(r);
  store_reduced(s, r);
}

/* h = -f (mod p). Carry-normalize f first so its limbs stay within the 2p
 * margin ed_fe_sub relies on. */
void ed_fe_neg(fe h, const fe f) {
  fe z, r;
  ed_fe_0(z);
  ed_fe_copy(r, f);
  carry_pass(r);
  carry_pass(r);
  ed_fe_sub(h, z, r);
}

int ed_fe_isnonzero(const fe f) {
  u8 s[32];
  u8 acc = 0;
  ed_fe_tobytes(s, f);
  for (usz i = 0; i < 32; i++) acc |= s[i];
  return acc != 0;
}

/* Least significant bit of the canonical representative. */
int ed_fe_isnegative(const fe f) {
  u8 s[32];
  ed_fe_tobytes(s, f);
  return s[0] & 1;
}

/* a == b (mod p), compared by canonical 32-byte encoding. */
int ed_fe_equal(const fe a, const fe b) {
  u8 sa[32], sb[32];
  u8 diff = 0;
  ed_fe_tobytes(sa, a);
  ed_fe_tobytes(sb, b);
  for (usz i = 0; i < 32; i++) diff |= sa[i] ^ sb[i];
  return diff == 0;
}
