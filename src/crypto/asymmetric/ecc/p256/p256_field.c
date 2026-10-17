#include "crypto/asymmetric/ecc/p256/p256_field_impl.h"

static u64 fe_add_raw(p256_fe t, const p256_fe a, const p256_fe b);

/* FIPS 186-4 D.1.2.3 / D.2.3. */
const p256_fe p256_p = {
    0xffffffffffffffffULL, 0x00000000ffffffffULL, 0x0000000000000000ULL,
    0xffffffff00000001ULL};

const p256_fe p256_n = {
    0xf3b9cac2fc632551ULL, 0xbce6faada7179e84ULL, 0xffffffffffffffffULL,
    0xffffffff00000000ULL};

/* Montgomery contexts (R = 2^256). Constants precomputed and cross-checked:
 * n0inv = -m[0]^-1 mod 2^64, rr = R^2 mod m, one = R mod m. */
const mont p256_mont_p = {
    {0xffffffffffffffffULL, 0x00000000ffffffffULL, 0x0000000000000000ULL,
     0xffffffff00000001ULL},
    {0x0000000000000003ULL, 0xfffffffbffffffffULL, 0xfffffffffffffffeULL,
     0x00000004fffffffdULL},
    {0x0000000000000001ULL, 0xffffffff00000000ULL, 0xffffffffffffffffULL,
     0x00000000fffffffeULL},
    0x0000000000000001ULL};

const mont p256_mont_n = {
    {0xf3b9cac2fc632551ULL, 0xbce6faada7179e84ULL, 0xffffffffffffffffULL,
     0xffffffff00000000ULL},
    {0x83244c95be79eea2ULL, 0x4699799c49bd6fa6ULL, 0x2845b2392b6bec59ULL,
     0x66e12d94f3d95620ULL},
    {0x0c46353d039cdaafULL, 0x4319055258e8617bULL, 0x0000000000000000ULL,
     0x00000000ffffffffULL},
    0xccd1c8aaee00bc4fULL};

void p256_fp_set(p256_fe r, const p256_fe a) {
  for (usz i = 0; i < 4; i++) r[i] = a[i];
}

int p256_fp_is_zero(const p256_fe a) {
  u64 d = 0;
  for (usz i = 0; i < 4; i++) d |= a[i];
  return d == 0;
}

int p256_fp_eq(const p256_fe a, const p256_fe b) {
  u64 d = 0;
  for (usz i = 0; i < 4; i++) d |= a[i] ^ b[i];
  return d == 0;
}

int p256_fp_lt(const p256_fe a, const p256_fe b) { return !p256_fe_ge(a, b); }

/* t = a + b (256-bit); returns the carry out of bit 255. */
static u64 fe_add_raw(p256_fe t, const p256_fe a, const p256_fe b) {
  unsigned __int128 c = 0;
  for (usz i = 0; i < 4; i++) {
    c += (unsigned __int128)a[i] + b[i];
    t[i] = (u64)c;
    c >>= 64;
  }
  return (u64)c;
}

void p256_fp_add(p256_fe r, fpab ab, const p256_fe m) {
  p256_fe t;
  u64     carry = fe_add_raw(t, ab.a, ab.b);
  /* Single subtract of m suffices since a,b < m (sum < 2m). */
  int over = carry || p256_fe_ge(t, m);
  if (over)
    p256_fe_sub_raw(r, t, m);
  else
    p256_fp_set(r, t);
}

void p256_fp_sub(p256_fe r, fpab ab, const p256_fe m) {
  if (p256_fe_ge(ab.a, ab.b))
    p256_fe_sub_raw(r, ab.a, ab.b);
  else {
    p256_fe t;
    p256_fe_sub_raw(t, ab.b, ab.a);
    p256_fe_sub_raw(r, m, t);
  }
}
