#include "crypto/asymmetric/ecc/p521/ecdsa_verify.h"

#include "crypto/asymmetric/ecc/p521/p521_point.h"

/* FIPS 186-4 Section 6.4.2. */

static const p521_fe p521ev_zero = {0};

/* Load a 66-byte scalar; valid only in [1, n-1]. */
static int p521ev_scalar(p521_fe v, const u8 b[66]) {
  fp521_from_be(v, b);
  return !fp521_is_zero(v) && fp521_lt(v, p521_n);
}

/* Load Q; valid only with both coordinates < p and on the curve (Q is
 * never infinity in this encoding, and the cofactor is 1). */
static int p521ev_pubkey(
    p521_fe x, p521_fe y, const u8 px[66], const u8 py[66]) {
  fp521_from_be(x, px);
  fp521_from_be(y, py);
  return fp521_lt(x, p521_p) && fp521_lt(y, p521_p) && p521_on_curve(x, y);
}

/* A digest of 66+ bytes (528+ bits) keeps its leftmost 521 bits: the first
 * 66 bytes shifted right by 7. */
static void p521ev_digest_cut(u8 e[66], const u8* d) {
  e[0] = (u8)(d[0] >> 7);
  for (usz i = 1; i < 66; i++) e[i] = (u8)((d[i - 1] << 1) | (d[i] >> 7));
}

/* A shorter digest is the integer itself, left-zero-extended. */
static void p521ev_digest_pad(u8 e[66], const u8* d, usz n) {
  for (usz i = 0; i < 66 - n; i++) e[i] = 0;
  for (usz i = 0; i < n; i++) e[66 - n + i] = d[i];
}

/* FIPS 186-4 6.4: e = leftmost min(521, 8*len) bits of the digest, then
 * mod n (e < 2^521 < 2n, so the zero-add's one conditional subtraction). */
static void p521ev_digest(p521_fe e, const u8* d, usz n) {
  u8 b[66];
  if (n >= 66)
    p521ev_digest_cut(b, d);
  else
    p521ev_digest_pad(b, d, n);
  fp521_from_be(e, b);
  fp521_add(e, e, p521ev_zero, p521_n);
}

typedef struct {
  p521_fe r, s, x, y;
} p521ev_in;

static int p521ev_load(
    p521ev_in* in, const u8* px, const u8* py, const u8* sr, const u8* ss) {
  return p521ev_scalar(in->r, sr) && p521ev_scalar(in->s, ss) &&
         p521ev_pubkey(in->x, in->y, px, py);
}

int ecdsa_p521_verify(
    const u8  pub_x[66],
    const u8  pub_y[66],
    const u8  sig_r[66],
    const u8  sig_s[66],
    const u8* digest,
    usz       digest_len) {
  p521ev_in in;
  p521_fe   e, w, u1, u2, rx;
  if (!p521ev_load(&in, pub_x, pub_y, sig_r, sig_s)) return 0;
  p521ev_digest(e, digest, digest_len);
  fp521_inv(w, in.s, p521_n); /* w = s^-1, u1 = e*w, u2 = r*w (mod n) */
  fp521_mul(u1, e, w, p521_n);
  fp521_mul(u2, in.r, w, p521_n);
  if (!p521_mul2_x(rx, u1, u2, in.x, in.y)) return 0;
  fp521_add(rx, rx, p521ev_zero, p521_n); /* x < p < 2n: x mod n */
  return fp521_eq(rx, in.r);
}
