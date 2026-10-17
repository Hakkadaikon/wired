#include "tls/handshake/core/tls/x25519_impl.h"

static void clamp(u8 e[32], const u8 scalar[32]);
static int  x25519_nonzero(const u8 out[32]);

/* Clamp the scalar per RFC 7748 (clear low 3 bits, set bit 254, clear 255). */
static void clamp(u8 e[32], const u8 scalar[32]) {
  for (usz i = 0; i < 32; i++) e[i] = scalar[i];
  e[0] &= 248;
  e[31] = (e[31] & 127) | 64;
}

/* Run the x25519_ladder for all 255 scalar bits, leaving the result in x2,z2.
 */
void x25519_ladder(fe x2, fe z2, const u8 e[32], const fe x1) {
  ladder_state st;
  u64          swap = 0;
  x25519_fe_1(st.x2);
  x25519_fe_0(st.z2);
  x25519_fe_copy(st.x3, x1);
  x25519_fe_1(st.z3);
  for (usz pos = 255; pos-- > 0;) {
    u64 bit = (e[pos / 8] >> (pos & 7)) & 1;
    swap ^= bit;
    x25519_fe_cswap(st.x2, st.x3, swap);
    x25519_fe_cswap(st.z2, st.z3, swap);
    swap = bit;
    x25519_ladder_step(&st, x1);
  }
  x25519_fe_cswap(st.x2, st.x3, swap);
  x25519_fe_cswap(st.z2, st.z3, swap);
  x25519_fe_copy(x2, st.x2);
  x25519_fe_copy(z2, st.z2);
}

/* RFC 7748 6.1: a low-order point yields an all-zero shared secret. Detect it
 * in constant time (OR-accumulate all bytes, branch only on the fold). */
static int x25519_nonzero(const u8 out[32]) {
  u8 d = 0;
  for (usz i = 0; i < 32; i++) d |= out[i];
  return d != 0;
}

/* Counts scalar multiplies so a test can pin "one server flight, one ECDHE"
 * (the connection key schedule must reuse sdrv's secret, not recompute it). */
static usz x25519_mult_count;

int wired_x25519(
    u8       out[X25519_LEN],
    const u8 scalar[X25519_LEN],
    const u8 point[X25519_LEN]) {
  fe x1, x2, z2, zinv;
  u8 e[32];
  x25519_mult_count++;
  clamp(e, scalar);
  x25519_fe_frombytes(x1, point);
  x25519_ladder(x2, z2, e, x1);
  x25519_fe_invert(zinv, z2);
  x25519_fe_mul(x2, x2, zinv);
  x25519_fe_tobytes(out, x2);
  return x25519_nonzero(out);
}

int wired_x25519_base(u8 out[X25519_LEN], const u8 scalar[X25519_LEN]) {
  u8 base[32] = {9};
  return wired_x25519(out, scalar, base);
}
