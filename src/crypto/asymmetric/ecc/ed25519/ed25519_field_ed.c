#include "crypto/asymmetric/ecc/ed25519/ed25519_field_impl.h"

static int  recover_x(fe x, const fe u, const fe v);
static int  decode_sign_fails(const fe x, int x_0);
static void apply_sign(fe x, int x_0);
static void decode_uv(fe u, fe v, const fe y);
static int  y_is_canonical(const fe y, const u8 in[32]);
static int  decode_xy(ge* p, const u8 in[32], int* x_0_out);
static int  ed_enc_is_identity(const u8 e[32]);

void ed_ge_scalarmult(ge* q, const u8 scalar[32], const ge* p) {
  ed_ge_zero(q);
  for (usz i = 256; i-- > 0;) {
    u8 bit = (scalar[i >> 3] >> (i & 7)) & 1;
    ed_ge_add(q, q, q);
    ge t;
    ed_ge_add(&t, q, p);
    ed_fe_cmov(q->X, t.X, bit);
    ed_fe_cmov(q->Y, t.Y, bit);
    ed_fe_cmov(q->Z, t.Z, bit);
    ed_fe_cmov(q->T, t.T, bit);
  }
}

void ed_ge_encode(u8 out[32], const ge* p) {
  fe zi, x, y;
  ed_fe_invert(zi, p->Z);
  ed_fe_mul(x, p->X, zi);
  ed_fe_mul(y, p->Y, zi);
  ed_fe_tobytes(out, y);
  out[31] ^= (u8)(ed_fe_isnegative(x) << 7);
}

/* Recover x from (u/v) per RFC 8032 5.1.3 step 2-3; returns 1 on success. */
static int recover_x(fe x, const fe u, const fe v) {
  fe v3, uv7, t, vx2, nu;
  ed_fe_sq(v3, v);
  ed_fe_mul(v3, v3, v); /* v^3 */
  ed_fe_sq(uv7, v3);
  ed_fe_mul(uv7, uv7, v);
  ed_fe_mul(uv7, uv7, u); /* u v^7 */
  ed_fe_pow_p58(t, uv7);
  ed_fe_mul(x, v3, u);
  ed_fe_mul(x, x, t); /* x = u v^3 (uv^7)^((p-5)/8) */
  ed_fe_sq(vx2, x);
  ed_fe_mul(vx2, vx2, v);
  ed_fe_neg(nu, u);
  if (ed_fe_equal(vx2, u)) {
    return 1;
  }
  ed_fe_sqrtm1(t);
  ed_fe_mul(x, x, t);
  return ed_fe_equal(vx2, nu);
}

/* x is zero while the sign bit x_0 demands x_0 = 1 (RFC 8032 5.1.3 step 4). */
static int decode_sign_fails(const fe x, int x_0) {
  return !ed_fe_isnonzero(x) && x_0;
}

/* Select the square root whose parity matches x_0 (RFC 8032 5.1.3 step 4). */
static void apply_sign(fe x, int x_0) {
  fe nx;
  ed_fe_neg(nx, x);
  ed_fe_cmov(x, nx, x_0 != ed_fe_isnegative(x));
}

/* u = y^2 - 1 and v = d y^2 + 1 from the decoded y (RFC 8032 5.1.3 step 2). */
static void decode_uv(fe u, fe v, const fe y) {
  fe one, dd;
  ed_fe_1(one);
  ed_fe_sq(u, y);
  ed_fe_sub(u, u, one);
  ed_fe_d(dd);
  ed_fe_mul(v, u, dd);
  ed_fe_add(v, v, dd);
  ed_fe_add(v, v, one);
}

/* 1 if the 255-bit y read from in (sign bit already excluded) is < p, i.e.
 * the encoding is the canonical one for this field element (RFC 8032 5.1.3
 * step 1: "If the resulting value is >= p, decoding fails"). Compares the
 * fully reduced encoding of y against the as-received bytes; they differ
 * only when y's raw value was in [p, 2^255). */
static int y_is_canonical(const fe y, const u8 in[32]) {
  u8 canon[32];
  u8 diff = 0;
  ed_fe_tobytes(canon, y);
  for (usz i = 0; i < 31; i++) {
    diff |= canon[i] ^ in[i];
  }
  diff |= canon[31] ^ (in[31] & 0x7f);
  return diff == 0;
}

/* Decode y and recover x (RFC 8032 5.1.3 steps 1-3). Returns 1 and leaves x_0
 * in *x_0_out on success; 0 if y is non-canonical or no square root exists. */
static int decode_xy(ge* p, const u8 in[32], int* x_0_out) {
  fe u, v;
  *x_0_out = in[31] >> 7;
  ed_fe_frombytes(p->Y, in);
  if (!y_is_canonical(p->Y, in)) {
    return 0;
  }
  decode_uv(u, v, p->Y);
  return recover_x(p->X, u, v);
}

/* The identity encodes as y = 1 with sign bit 0: 0x01 then 31 zero bytes. */
static int ed_enc_is_identity(const u8 e[32]) {
  u8 diff = (u8)(e[0] ^ 0x01);
  for (usz i = 1; i < 32; i++) {
    diff |= e[i];
  }
  return diff == 0;
}

int ed_ge_is_small_order(const ge* p) {
  ge q;
  u8 e[32];
  ed_ge_add(&q, p, p);
  ed_ge_add(&q, &q, &q);
  ed_ge_add(&q, &q, &q); /* q = [8]p */
  ed_ge_encode(e, &q);
  return ed_enc_is_identity(e);
}

int ed_ge_decode(ge* p, const u8 in[32]) {
  int x_0;
  if (!decode_xy(p, in, &x_0)) {
    return 0;
  }
  if (decode_sign_fails(p->X, x_0)) {
    return 0;
  }
  apply_sign(p->X, x_0);
  ed_fe_1(p->Z);
  ed_fe_mul(p->T, p->X, p->Y);
  return 1;
}
