#ifndef QUIC_UTIL_BE_H
#define QUIC_UTIL_BE_H

#include "common/platform/sys/syscall.h"

/* Big-endian stores shared across the network and codec domains. Inline so
 * they need no translation unit and never clash across included sources. */

static inline void quic_put_be16(u8 *p, u16 v) {
  p[0] = (u8)(v >> 8);
  p[1] = (u8)v;
}

static inline void quic_put_be32(u8 *p, u32 v) {
  p[0] = (u8)(v >> 24);
  p[1] = (u8)(v >> 16);
  p[2] = (u8)(v >> 8);
  p[3] = (u8)v;
}

#endif
