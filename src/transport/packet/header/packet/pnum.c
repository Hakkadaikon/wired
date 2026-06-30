#include "transport/packet/header/packet/pnum.h"

/* RFC 9000 A.2: the fewest bytes b (1..4) with 2*num_unacked < 2^(8b),
 * where num_unacked is the range from largest_acked to the packet sent. */
usz quic_pnum_len(u64 full_pn, u64 largest_acked) {
  u64 need = (full_pn - largest_acked) * 2;
  usz b    = 1;
  while (b < 4 && need >= ((u64)1 << (8 * b))) b++;
  return b;
}

/* Write the low nbytes of v big-endian. */
usz quic_pnum_encode(u8 *buf, u64 full_pn, usz nbytes) {
  usz i = nbytes;
  while (i-- > 0) {
    buf[i] = (u8)(full_pn & 0xFF);
    full_pn >>= 8;
  }
  return nbytes;
}

static u64 read_be(const u8 *buf, usz nbytes) {
  u64 v = 0;
  for (usz i = 0; i < nbytes; i++) v = (v << 8) | buf[i];
  return v;
}

/* The candidate is a full window below expected and can be lifted safely. */
static int below_window(u64 candidate, u64 expected, u64 win) {
  return candidate + win / 2 <= expected && candidate + win > candidate;
}

/* The candidate is a full window above expected and can be lowered safely. */
static int above_window(u64 candidate, u64 expected, u64 win) {
  return candidate > expected + win / 2 && candidate >= win;
}

/* RFC 9000 A.3: pick the candidate nearest to expected_pn that ends in the
 * truncated bits. win = 1<<bits; candidate sits in [expected-win/2, +win/2). */
static u64 nearest(u64 candidate, u64 expected, u64 win) {
  if (below_window(candidate, expected, win)) return candidate + win;
  if (above_window(candidate, expected, win)) return candidate - win;
  return candidate;
}

u64 quic_pnum_decode(const u8 *buf, usz nbytes, u64 largest_pn) {
  u64 truncated = read_be(buf, nbytes);
  u64 bits      = nbytes * 8;
  u64 win       = (u64)1 << bits;
  u64 expected  = largest_pn + 1;
  u64 candidate = (expected & ~(win - 1)) | truncated;
  return nearest(candidate, expected, win);
}
