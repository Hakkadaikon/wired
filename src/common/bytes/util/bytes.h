#ifndef UTIL_BYTES_H
#define UTIL_BYTES_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/**
 * @file
 * Cursor byte-copy helpers shared by the frame codecs. Inline so multiple
 * codec translation units can use them without redefining a static helper.
 */

/**
 * Append src into buf at *off.
 *
 * Both buf and src are borrowed views: no ownership transfers and nothing is
 * copied into new storage, so buf and src must stay alive (and unmoved) only
 * for the duration of this call.
 *
 * @param buf destination buffer (its .n is the total capacity)
 * @param off write cursor into buf; advanced by src.n on success
 * @param src bytes to append
 * @return 1 ok, 0 if no room.
 */
static inline int bytes_put(wired_mspan buf, usz* off, wired_span src) {
  if (*off + src.n > buf.n) return 0;
  for (usz i = 0; i < src.n; i++) buf.p[*off + i] = src.p[i];
  *off += src.n;
  return 1;
}

/**
 * Copy dst.n bytes into dst from *off (buf total).
 *
 * Both buf and dst are borrowed views: no ownership transfers, and each must
 * stay alive (and unmoved) only for the duration of this call.
 *
 * @param buf source buffer to read from
 * @param off read cursor into buf; advanced by dst.n on success
 * @param dst destination; exactly dst.n bytes are copied
 * @return 1 ok, 0 if truncated.
 */
static inline int bytes_take(wired_span buf, usz* off, wired_mspan dst) {
  if (*off + dst.n > buf.n) return 0;
  for (usz i = 0; i < dst.n; i++) dst.p[i] = buf.p[*off + i];
  *off += dst.n;
  return 1;
}

/**
 * Freestanding byte copy.
 *
 * Even under -ffreestanding -fno-builtin the compiler still emits
 * `memcpy`/`memset` calls for struct and array copies/zeroing (e.g.
 * modexp.c, ed25519_sign.c, respond.c), and with -nostdlib no libc supplies
 * them. The SDK owns these primitives; each freestanding binary's mandatory
 * libc-named `memcpy`/`memset` shim (the symbol names the compiler
 * hard-codes) just forwards to these.
 *
 * @param dst destination buffer (must not overlap src)
 * @param src source buffer
 * @param n   number of bytes to copy
 * @return dst
 */
static inline void* bytes_memcpy(void* dst, const void* src, usz n) {
  u8*       d = dst;
  const u8* s = src;
  for (usz i = 0; i < n; i++) d[i] = s[i];
  return dst;
}

/**
 * Freestanding byte fill. See bytes_memcpy() for why the SDK owns this.
 *
 * @param dst buffer to fill
 * @param c   fill byte (truncated to u8)
 * @param n   number of bytes to fill
 * @return dst
 */
static inline void* bytes_memset(void* dst, int c, usz n) {
  u8* d = dst;
  for (usz i = 0; i < n; i++) d[i] = (u8)c;
  return dst;
}

/**
 * Freestanding NUL-terminated string length. src/ has no libc strlen.
 *
 * @param s NUL-terminated string
 * @return number of bytes before the terminating NUL
 */
static inline usz wired_cstr_len(const char* s) {
  usz n = 0;
  while (s[n]) n++;
  return n;
}

/**
 * ASCII lowercase of one octet (A-Z -> a-z, everything else unchanged).
 *
 * @param c input octet
 * @return lowercased octet
 */
static inline u8 ascii_lower(u8 c) {
  return (c >= 'A' && c <= 'Z') ? (u8)(c | 0x20) : c;
}

/**
 * RFC 6125 6.4.1: ASCII case-insensitive equality of two DNS-name-shaped byte
 * spans (host names, SNI values). Non-ASCII bytes compare bytewise (no
 * folding applied outside A-Z).
 *
 * @param a first span
 * @param b second span
 * @return 1 if equal length and equal after ASCII case-folding, 0 otherwise.
 */
static inline int ascii_dns_eq(wired_span a, wired_span b) {
  usz diff = 0;
  if (a.n != b.n) return 0;
  for (usz i = 0; i < a.n; i++)
    diff |= (usz)(ascii_lower(a.p[i]) ^ ascii_lower(b.p[i]));
  return diff == 0;
}

#endif
