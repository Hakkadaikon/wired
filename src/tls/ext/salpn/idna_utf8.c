#include "tls/ext/salpn/idna_impl.h"

/* RFC 3629 3: strict UTF-8 decoding for salpn_idna_to_ascii. */

#define IDNA_BAD 0xFFFFFFFFu

/* RFC 3629 3: UTF-8 sequence length by lead byte >> 3 (0 = not a lead). */
static const u8 IDNA_U8LEN[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                  1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
                                  0, 0, 2, 2, 2, 2, 3, 3, 4, 0};
/* The lead byte's payload bits, and the least code point (no overlong
 * form), by sequence length. */
static const u8  IDNA_U8MASK[5] = {0, 0x7F, 0x1F, 0x0F, 0x07};
static const u32 IDNA_U8MIN[5]  = {0, 0, 0x80, 0x800, 0x10000};

/* One continuation byte folded in; IDNA_BAD stays bad. */
static u32 idna_u8_cont(u32 v, u8 c) {
  return (c & 0xC0) == 0x80 && v != IDNA_BAD ? (v << 6 | (c & 0x3Fu))
                                             : IDNA_BAD;
}

/* A scalar value (RFC 3629 3: no surrogate, at most 0x10FFFF) in its
 * shortest form. */
static int idna_cp_ok(u32 v, usz len) {
  return v >= IDNA_U8MIN[len] && v <= 0x10FFFF && v - 0xD800 > 0x7FF;
}

/* The len-byte sequence at s folded into one value (IDNA_BAD on a bad
 * continuation byte). */
static u32 idna_u8_fold(const u8* s, usz len) {
  u32 v = s[0] & IDNA_U8MASK[len];
  for (usz i = 1; i < len; i++) {
    v = idna_u8_cont(v, s[i]);
  }
  return v;
}

/* A lead byte (len != 0) whose whole sequence is within the n bytes. */
static int idna_len_ok(usz len, usz n) { return len != 0 && len <= n; }

/* Decode the code point at s (n bytes left) into *cp; returns its byte
 * length, or 0 on malformed UTF-8. */
static usz idna_utf8_one(const u8* s, usz n, u32* cp) {
  usz len = IDNA_U8LEN[s[0] >> 3];
  if (!idna_len_ok(len, n)) {
    return 0;
  }
  *cp = idna_u8_fold(s, len);
  return idna_cp_ok(*cp, len) ? len : 0;
}

/* Still decoding: the last code point was good and bytes remain. */
static int idna_decode_more(usz k, usz at, usz n) { return k != 0 && at < n; }

usz salpn_idna_decode_label(wired_span l, u32* cps) {
  usz n = 0, at = 0, k = 1;
  while (idna_decode_more(k, at, l.n)) {
    k = idna_utf8_one(l.p + at, l.n - at, &cps[n++]);
    at += k;
  }
  return k != 0 ? n : 0;
}
