#ifndef QUIC_UTIL_BYTES_H
#define QUIC_UTIL_BYTES_H

#include "common/platform/sys/syscall.h"

/* Cursor byte-copy helpers shared by the frame codecs. Inline so multiple
 * codec translation units can use them without redefining a static helper. */

/* Append n bytes of src at *off (cap total). Returns 1 ok, 0 if no room. */
static inline int quic_put_bytes(
    u8 *buf, usz cap, usz *off, const u8 *src, usz n) {
  if (*off + n > cap) return 0;
  for (usz i = 0; i < n; i++) buf[*off + i] = src[i];
  *off += n;
  return 1;
}

/* Copy n bytes into dst from *off (len total). Returns 1 ok, 0 if truncated. */
static inline int quic_take_bytes(
    const u8 *buf, usz len, usz *off, u8 *dst, usz n) {
  if (*off + n > len) return 0;
  for (usz i = 0; i < n; i++) dst[i] = buf[*off + i];
  *off += n;
  return 1;
}

#endif
