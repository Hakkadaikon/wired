#ifndef UTIL_NUM_H
#define UTIL_NUM_H

#include "common/platform/sys/syscall.h"

/* Tiny scalar helpers shared across domains. Inline so they need no TU. */

static inline u64 u64_min(u64 a, u64 b) { return a < b ? a : b; }
static inline u64 u64_max(u64 a, u64 b) { return a > b ? a : b; }
static inline u64 u64_absdiff(u64 a, u64 b) { return a > b ? a - b : b - a; }

/* *out = a + b; returns 0 (and leaves *out alone) if that passes 2^64-1. */
static inline int u64_add_ok(u64 a, u64 b, u64* out) {
  if (b > (u64)-1 - a) return 0;
  *out = a + b;
  return 1;
}

/* 1 if v is in list (n entries), else 0. */
static inline int u32_in(u32 v, const u32* list, usz n) {
  for (usz i = 0; i < n; i++)
    if (list[i] == v) return 1;
  return 0;
}

#endif
