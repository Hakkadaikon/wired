#ifndef QUIC_UTIL_BE_H
#define QUIC_UTIL_BE_H

#include "common/platform/sys/syscall.h"

/* Big-endian stores shared across the network and codec domains. Inline so
 * they need no translation unit and never clash across included sources. */

static inline void quic_put_be16(u8* p, u16 v) {
  p[0] = (u8)(v >> 8);
  p[1] = (u8)v;
}

static inline void quic_put_be32(u8* p, u32 v) {
  p[0] = (u8)(v >> 24);
  p[1] = (u8)(v >> 16);
  p[2] = (u8)(v >> 8);
  p[3] = (u8)v;
}

static inline u32 quic_get_be32(const u8* p) {
  return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static inline void quic_put_be64(u8* p, u64 v) {
  quic_put_be32(p, (u32)(v >> 32));
  quic_put_be32(p + 4, (u32)v);
}

static inline u64 quic_get_be64(const u8* p) {
  return ((u64)quic_get_be32(p) << 32) | (u64)quic_get_be32(p + 4);
}

#endif
