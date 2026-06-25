#ifndef QUIC_UTIL_NUM_H
#define QUIC_UTIL_NUM_H

#include "sys/syscall.h"

/* Tiny scalar helpers shared across domains. Inline so they need no TU. */

static inline u64 quic_u64_min(u64 a, u64 b) { return a < b ? a : b; }
static inline u64 quic_u64_max(u64 a, u64 b) { return a > b ? a : b; }
static inline u64 quic_u64_absdiff(u64 a, u64 b) { return a > b ? a - b : b - a; }

#endif
