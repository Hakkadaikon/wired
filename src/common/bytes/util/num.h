#ifndef QUIC_UTIL_NUM_H
#define QUIC_UTIL_NUM_H

#include "common/platform/sys/syscall.h"

/* Tiny scalar helpers shared across domains. Inline so they need no TU. */

static inline u64 quic_u64_min(u64 a, u64 b) { return a < b ? a : b; }
static inline u64 quic_u64_max(u64 a, u64 b) { return a > b ? a : b; }
static inline u64 quic_u64_absdiff(u64 a, u64 b) {
  return a > b ? a - b : b - a;
}

/* 1 if v is in list (n entries), else 0. */
static inline int quic_u32_in(u32 v, const u32* list, usz n) {
  for (usz i = 0; i < n; i++)
    if (list[i] == v) return 1;
  return 0;
}

#endif
