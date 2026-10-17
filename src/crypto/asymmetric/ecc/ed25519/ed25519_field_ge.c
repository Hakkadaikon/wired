#include "crypto/asymmetric/ecc/ed25519/ed25519_field_impl.h"

static void fe_basex(fe out);
static void fe_basey(fe out);
static void ge_add_ab(fe a, fe b, const ge* p1, const ge* p2);
static void ge_add_cd(fe c, fe d, const ge* p1, const ge* p2);

/* Constant-time-ish conditional move: h <- g when cond != 0. */
void ed_fe_cmov(fe h, const fe g, int cond) {
  u64 mask = (u64)(0 - (u64)(cond != 0));
  for (usz i = 0; i < 5; i++) {
    h[i] ^= mask & (h[i] ^ g[i]);
  }
}

/* sqrt(-1) mod p, needed when v*x^2 = -u (RFC 8032 5.1.3 case 2). */
void ed_fe_sqrtm1(fe out) {
  static const u8 b[32] = {0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
                           0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
                           0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
                           0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b};
  ed_fe_frombytes(out, b);
}

/* Ed25519 curve constant d (RFC 8032 5.1) loaded into a field element. */
void ed_fe_d(fe out) {
  static const u8 b[32] = {0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
                           0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
                           0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
                           0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52};
  ed_fe_frombytes(out, b);
}

void ed_ge_zero(ge* p) {
  ed_fe_0(p->X);
  ed_fe_1(p->Y);
  ed_fe_1(p->Z);
  ed_fe_0(p->T);
}

/* Base point B x coordinate (RFC 8032 5.1). */
static void fe_basex(fe out) {
  static const u8 b[32] = {0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
                           0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
                           0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
                           0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21};
  ed_fe_frombytes(out, b);
}

/* Base point B y coordinate = 4/5 (RFC 8032 5.1). */
static void fe_basey(fe out) {
  static const u8 b[32] = {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                           0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                           0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                           0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
  ed_fe_frombytes(out, b);
}

void ed_ge_base(ge* p) {
  fe_basex(p->X);
  fe_basey(p->Y);
  ed_fe_1(p->Z);
  ed_fe_mul(p->T, p->X, p->Y);
}

/* a = (Y1-X1)(Y2-X2), b = (Y1+X1)(Y2+X2) (RFC 8032 5.1.4). */
static void ge_add_ab(fe a, fe b, const ge* p1, const ge* p2) {
  fe t;
  ed_fe_sub(a, p1->Y, p1->X);
  ed_fe_sub(t, p2->Y, p2->X);
  ed_fe_mul(a, a, t);
  ed_fe_add(b, p1->Y, p1->X);
  ed_fe_add(t, p2->Y, p2->X);
  ed_fe_mul(b, b, t);
}

/* c = T1*2*d*T2, d = Z1*2*Z2 (RFC 8032 5.1.4). */
static void ge_add_cd(fe c, fe d, const ge* p1, const ge* p2) {
  fe d2;
  ed_fe_d(d2);
  ed_fe_add(d2, d2, d2); /* 2*d */
  ed_fe_mul(c, p1->T, p2->T);
  ed_fe_mul(c, c, d2);
  ed_fe_mul(d, p1->Z, p2->Z);
  ed_fe_add(d, d, d);
}

void ed_ge_add(ge* p3, const ge* p1, const ge* p2) {
  fe a, b, c, d, e, f, g, h;
  ge_add_ab(a, b, p1, p2);
  ge_add_cd(c, d, p1, p2);
  ed_fe_sub(e, b, a);
  ed_fe_sub(f, d, c);
  ed_fe_add(g, d, c);
  ed_fe_add(h, b, a);
  ed_fe_mul(p3->X, e, f);
  ed_fe_mul(p3->Y, g, h);
  ed_fe_mul(p3->T, e, h);
  ed_fe_mul(p3->Z, f, g);
}
