#include "crypto/pki/encoding/x509/dirstring_impl.h"

static int  is_space(u8 c);
static int  has_non_ascii(wired_span s);
static void cursor_init(dirstring_cursor* c, wired_span s);
static void cursor_skip_space_run(dirstring_cursor* c);
static int  cursor_next_space(dirstring_cursor* c, u8* out);
static int  cursor_next(dirstring_cursor* c, u8* out);
static int  step_equal(dirstring_cursor* a, dirstring_cursor* b, int* more);
static int  dirstring_bytes_eq(wired_span a, wired_span b);
static int  either_non_ascii(wired_span a, wired_span b);
static int  cursors_equal(dirstring_cursor* a, dirstring_cursor* b);

/* RFC 4518 2.6.1 (ASCII scope, see dirstring.h). Only the plain space
 * (0x20) is treated as insignificant whitespace; tab/newline are not
 * FOLDed by this SDK's simplified preparation. */
static int is_space(u8 c) { return c == 0x20; }

/* 1 if any octet in s is outside the ASCII range this SDK case-folds
 * (>= 0x80): a multi-byte DirectoryString encoding (UTF-8 non-ASCII,
 * BMPString, UniversalString, TeletexString 8-bit) this SDK does not
 * decode. */
static int has_non_ascii(wired_span s) {
  for (usz i = 0; i < s.n; i++) {
    if (s.p[i] & 0x80) {
      return 1;
    }
  }
  return 0;
}

static void cursor_init(dirstring_cursor* c, wired_span s) {
  c->s       = s;
  c->i       = 0;
  c->emitted = 0;
}

/* Advance past a run of one or more spaces starting at c->i (caller has
 * already confirmed c->i is a space). */
static void cursor_skip_space_run(dirstring_cursor* c) {
  while (c->i < c->s.n && is_space(c->s.p[c->i])) {
    c->i++;
  }
}

/* c->i is a space: consume the run. A leading run (nothing emitted yet)
 * produces no character of its own -- instead, go on to whatever the run's
 * end actually is (more content, or the true end of the string), since a
 * single cursor_next call must always resolve to either a real character or
 * genuine exhaustion, never a silent "skipped, call me again". An internal
 * run (something already emitted, more content follows) produces one
 * normalized space; a trailing run (nothing follows) produces nothing. */
static int cursor_next_space(dirstring_cursor* c, u8* out) {
  int was_emitted = c->emitted;
  cursor_skip_space_run(c);
  if (!was_emitted) {
    return cursor_next(c, out);
  }
  if (c->i >= c->s.n) {
    return 0;
  }
  *out = 0x20;
  return 1;
}

/* Pull the next normalized character out of *c into *out. Returns 1 if a
 * character was produced, 0 at end of input. */
static int cursor_next(dirstring_cursor* c, u8* out) {
  if (c->i >= c->s.n) {
    return 0;
  }
  if (is_space(c->s.p[c->i])) {
    return cursor_next_space(c, out);
  }
  *out = ascii_lower(c->s.p[c->i]);
  c->i++;
  c->emitted = 1;
  return 1;
}

/* Both cursors produce the same next normalized character (or both are
 * exhausted). */
static int step_equal(dirstring_cursor* a, dirstring_cursor* b, int* more) {
  u8  ca, cb;
  int ha = cursor_next(a, &ca);
  int hb = cursor_next(b, &cb);
  if (ha != hb) {
    return 0;
  }
  *more = ha;
  return !ha || ca == cb;
}

/* Byte-exact comparison (RFC 4518 preparation skipped). */
static int dirstring_bytes_eq(wired_span a, wired_span b) {
  usz diff = 0;
  if (a.n != b.n) {
    return 0;
  }
  for (usz i = 0; i < a.n; i++) {
    diff |= (usz)(a.p[i] ^ b.p[i]);
  }
  return diff == 0;
}

/* Either operand carries a byte this SDK does not case-fold (see dirstring.h
 * on why that falls back to byte-exact comparison). */
static int either_non_ascii(wired_span a, wired_span b) {
  return has_non_ascii(a) || has_non_ascii(b);
}

/* Drain both cursors in lockstep; 1 if every step matched through to EOF. */
static int cursors_equal(dirstring_cursor* a, dirstring_cursor* b) {
  int more = 1;
  while (more) {
    if (!step_equal(a, b, &more)) {
      return 0;
    }
  }
  return 1;
}

int x509_dirstring_ci_equal(wired_span a, wired_span b) {
  dirstring_cursor ca, cb;
  if (either_non_ascii(a, b)) {
    return dirstring_bytes_eq(a, b);
  }
  cursor_init(&ca, a);
  cursor_init(&cb, b);
  return cursors_equal(&ca, &cb);
}
