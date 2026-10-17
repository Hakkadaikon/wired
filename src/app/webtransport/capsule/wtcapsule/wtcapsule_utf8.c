#include "app/webtransport/capsule/wtcapsule/wtcapsule_impl.h"

static usz utf8_long_seq_len(u8 lead);
static usz utf8_multibyte_len(u8 lead);
static usz utf8_seq_len(u8 lead);
static int utf8_continuation_byte_ok(const u8* p, usz k);
static int utf8_continuations_shaped(const u8* p, usz n);
static int utf8_continuations_ok(wired_span msg, usz i, usz n);
static int utf8_3byte_shape_ok(const u8* p);
static int utf8_4byte_shape_ok(const u8* p);
static int utf8_shape_ok(const u8* p, usz n);
static int utf8_valid_at(wired_span msg, usz i, usz n);
static int utf8_at_ok(wired_span msg, usz i, usz* n);
static int utf8_seq_fits(wired_span msg, usz i, usz cap, usz* n);
static usz utf8_truncate_scan(wired_span msg, usz cap);

/* RFC 3629 SS3: byte length of a 3- or 4-byte lead, 0 if lead (already
 * known to be >= 0xE0, utf8_multibyte_len's own check) encodes past
 * U+10FFFF -- split out purely to keep each caller's branch count at the
 * CCN gate. */
static usz utf8_long_seq_len(u8 lead) {
  if (lead < 0xF0) return 3;
  return lead < 0xF5 ? 4 : 0;
}

/* RFC 3629 SS3: byte length of a 2/3/4-byte lead, 0 if lead (already known
 * to be >= 0x80, utf8_seq_len's own check) is a continuation byte or an
 * overlong C0/C1 lead. */
static usz utf8_multibyte_len(u8 lead) {
  if (lead < 0xC2) return 0;
  return lead < 0xE0 ? 2 : utf8_long_seq_len(lead);
}

/* RFC 3629 SS3: byte length of the UTF-8 sequence lead starts, 0 if lead is
 * not a valid lead byte at all. */
static usz utf8_seq_len(u8 lead) {
  return lead < 0x80 ? 1 : utf8_multibyte_len(lead);
}

/* 1 iff msg[i+1 .. i+n-1] are all continuation bytes (0x80-0xBF) -- the
 * generic shape check every multi-byte sequence needs regardless of length,
 * so utf8_valid_at itself only branches on the sequence-specific rules. */
static int utf8_continuation_byte_ok(const u8* p, usz k) {
  return (p[k] & 0xC0) == 0x80;
}

/* 1 iff every one of n-1 continuation bytes starting right after lead p[0]
 * is well-formed -- the bytes-in-range half of utf8_continuations_ok,
 * split out so the "does the sequence even fit" bounds check stays its own
 * branch. */
static int utf8_continuations_shaped(const u8* p, usz n) {
  for (usz k = 1; k < n; k++)
    if (!utf8_continuation_byte_ok(p, k)) return 0;
  return 1;
}

static int utf8_continuations_ok(wired_span msg, usz i, usz n) {
  if (i + n > msg.n) return 0;
  return utf8_continuations_shaped(msg.p + i, n);
}

/* RFC 3629 SS3: reject the two shapes that are structurally 2/3-byte
 * sequences but never valid scalar values -- an overlong 2-byte sequence
 * (lead 0xC0/0xC1, already excluded by utf8_seq_len) is impossible here, so
 * the remaining disallowed shapes are a 3-byte lead 0xE0 whose second byte
 * is an overlong continuation (< 0xA0), and the UTF-16 surrogate range
 * (lead 0xED, second byte 0xA0-0xBF). */
static int utf8_3byte_shape_ok(const u8* p) {
  if (p[0] == 0xE0) return p[1] >= 0xA0;
  if (p[0] == 0xED) return p[1] < 0xA0;
  return 1;
}

/* RFC 3629 SS3: a 4-byte lead's second byte must stay within the Unicode
 * range -- 0xF0 forbids an overlong second byte (< 0x90), and 0xF4 forbids
 * one that would reach past U+10FFFF (>= 0x90). */
static int utf8_4byte_shape_ok(const u8* p) {
  if (p[0] == 0xF0) return p[1] >= 0x90;
  if (p[0] == 0xF4) return p[1] < 0x90;
  return 1;
}

/* RFC 3629 SS3: the overlong/surrogate/out-of-range exclusions only a 3- or
 * 4-byte lead can violate (a 1- or 2-byte sequence has no such exclusion
 * left once utf8_seq_len already rejected an overlong C0/C1 lead). */
static int utf8_shape_ok(const u8* p, usz n) {
  if (n == 3) return utf8_3byte_shape_ok(p);
  return n == 4 ? utf8_4byte_shape_ok(p) : 1;
}

/* 1 iff the sequence of length n starting at msg[i] is shaped correctly per
 * RFC 3629 SS3. */
static int utf8_valid_at(wired_span msg, usz i, usz n) {
  return utf8_continuations_ok(msg, i, n) && utf8_shape_ok(msg.p + i, n);
}

/* 1 iff msg[i] starts a sequence this SDK accepts -- the one point where a
 * zero-length-or-invalid sequence turns into a reject, split out so the
 * scanning loop itself carries only the loop condition. */
static int utf8_at_ok(wired_span msg, usz i, usz* n) {
  *n = utf8_seq_len(msg.p[i]);
  return *n && utf8_valid_at(msg, i, *n);
}

int wtcapsule_utf8_valid(wired_span msg) {
  usz i = 0, n;
  while (i < msg.n && utf8_at_ok(msg, i, &n)) i += n;
  return i == msg.n;
}

/* 1 iff the sequence starting at msg[i] still fits before cap. A byte that
 * starts no sequence (seq_len 0) also stops the scan there, so an invalid
 * byte ends the prefix instead of looping forever. */
static int utf8_seq_fits(wired_span msg, usz i, usz cap, usz* n) {
  *n = utf8_seq_len(msg.p[i]);
  return *n && i + *n <= cap;
}

/* The scan loop itself, once cap is already known to be the shorter bound
 * (cap < msg.n) -- split out so wtcapsule_utf8_truncate_len's own early
 * "no truncation needed" return stays its only other branch (CCN). */
static usz utf8_truncate_scan(wired_span msg, usz cap) {
  usz i = 0, n;
  while (i < cap && utf8_seq_fits(msg, i, cap, &n)) i += n;
  return i;
}

usz wtcapsule_utf8_truncate_len(wired_span msg, usz cap) {
  return cap >= msg.n ? msg.n : utf8_truncate_scan(msg, cap);
}
