#include "transport/recovery/congestion/cc/cubic.h"

/* Digit-by-digit integer cube root (Hacker's Delight 11-2 shape). */
static u64 icbrt(u64 x) {
  u64 y = 0;
  for (int s = 63; s >= 0; s -= 3) {
    u64 b;
    y = 2 * y;
    b = 3 * y * (y + 1) + 1;
    if ((x >> s) >= b) {
      x -= b << s;
      y++;
    }
  }
  return y;
}

u64 quic_cubic_k_ms(u64 w_max_seg) { return icbrt(w_max_seg * 750000000u); }

/* |t - K| capped so the cube fits i64 (100s past K is far beyond any real
 * epoch between losses at these window sizes). */
#define CUBIC_D_CAP 100000

/* C * m^3 rounded to the nearest segment (C/1e9 folded to 1/2.5e9).
 * Rounding, not truncation: the concave side must reach exactly
 * beta * W_max at t = 0 despite K itself being a truncated cube root. */
static u64 cubic_mag(u64 m) {
  if (m > CUBIC_D_CAP) m = CUBIC_D_CAP;
  return (m * m * m + 1250000000u) / 2500000000u;
}

static i64 cubic_term(i64 d) {
  u64 t = cubic_mag((u64)(d < 0 ? -d : d));
  return d < 0 ? -(i64)t : (i64)t;
}

u64 quic_cubic_w(u64 t_ms, u64 k_ms, u64 w_max_seg) {
  i64 w = (i64)w_max_seg + cubic_term((i64)t_ms - (i64)k_ms);
  return w > 0 ? (u64)w : 0;
}

u64 quic_cubic_wmax_fastconv(u64 w_seg, u64 prev_wmax_seg) {
  if (w_seg < prev_wmax_seg) return w_seg * 17 / 20;
  return w_seg;
}
