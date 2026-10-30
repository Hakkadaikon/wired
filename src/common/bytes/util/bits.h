#ifndef UTIL_BITS_H
#define UTIL_BITS_H

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"
#include "common/platform/sys/syscall.h"

/* A bitmap over a byte array: bit i lives in m[i / 8]. Shared by the
 * receive windows that mark which offsets arrived. Inline so they need no
 * TU. */

static inline int bits_get(const u8* m, usz i) {
  return (m[i / 8] >> (i % 8)) & 1;
}

static inline void bits_set(u8* m, usz i, int v) {
  m[i / 8] = (u8)((m[i / 8] & ~(1u << (i % 8))) | ((v != 0) << (i % 8)));
}

/* Set bits [lo, hi) one at a time. */
static inline void bits_set_run(u8* m, usz lo, usz hi) {
  for (usz i = lo; i < hi; i++) {
    bits_set(m, i, 1);
  }
}

/* Set bits [lo, lo + n): the partial bytes at either end bit by bit, the
 * whole bytes between them at once. */
static inline void bits_fill(u8* m, usz lo, usz n) {
  usz hi = lo + n;
  usz a  = (usz)u64_min((lo + 7) / 8 * 8, hi);
  usz b  = (usz)u64_max(hi / 8 * 8, a);
  bits_set_run(m, lo, a);
  bytes_memset(m + a / 8, 0xff, (b - a) / 8);
  bits_set_run(m, b, hi);
}

/* m[i], 0 past the nb-byte bitmap. */
static inline u8 bits_byte_at(const u8* m, usz nb, usz i) {
  return i < nb ? m[i] : 0;
}

/* Slide an nbits-long bitmap (nbits a multiple of 8) down by n: bit i takes
 * bit i + n and the top n bits clear. Byte at a time; reading ahead of the
 * byte being written keeps it safe in place. */
static inline void bits_shift_down(u8* m, usz nbits, usz n) {
  usz nb = nbits / 8, q = n / 8, r = n % 8;
  for (usz k = 0; k < nb; k++) {
    u32 two =
        bits_byte_at(m, nb, k + q) | ((u32)bits_byte_at(m, nb, k + q + 1) << 8);
    m[k] = (u8)(two >> r);
  }
}

#endif
