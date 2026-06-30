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

/* Freestanding byte fill / copy. Even under -ffreestanding -fno-builtin the
 * compiler still emits `memcpy`/`memset` calls for struct and array
 * copies/zeroing (e.g. modexp.c, ed25519_sign.c, respond.c), and with
 * -nostdlib no libc supplies them. The SDK owns these primitives; each
 * freestanding binary's mandatory libc-named `memcpy`/`memset` shim (the symbol
 * names the compiler hard-codes) just forwards to these. */
static inline void *quic_memcpy(void *dst, const void *src, usz n) {
  u8       *d = dst;
  const u8 *s = src;
  for (usz i = 0; i < n; i++) d[i] = s[i];
  return dst;
}

static inline void *quic_memset(void *dst, int c, usz n) {
  u8 *d = dst;
  for (usz i = 0; i < n; i++) d[i] = (u8)c;
  return dst;
}

#endif
