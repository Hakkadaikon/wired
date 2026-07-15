#include "app/http3/server/hq09/hq09.h"

/* 1 if c is a newline byte ("\r" or "\n") -- split out so hq09_trim_newlines'
 * own loop guard stays a single comparison (a bare `||` inline would add to
 * the enclosing while's CCN). */
static int hq09_is_newline(u8 c) { return c == '\r' || c == '\n'; }

/* Trailing "\r\n"/"\n" bytes at line's end (mirrors the reference server's
 * TrimRight("\r\n")). Returns the trimmed length. */
static usz hq09_trim_newlines(quic_span line) {
  usz n = line.n;
  while (n > 0 && hq09_is_newline(line.p[n - 1])) n--;
  return n;
}

/* Trailing bare spaces at line's end (mirrors TrimRight(" ")), applied
 * after hq09_trim_newlines. */
static usz hq09_trim_spaces(const u8* p, usz n) {
  while (n > 0 && p[n - 1] == ' ') n--;
  return n;
}

/* 1 if p[i] differs from want[i] anywhere in [0, wlen) -- split out so the
 * caller's loop stays a single-condition while (mirrors the newline-trim
 * split above). */
static int hq09_bytes_differ(const u8* p, const u8* want, usz wlen) {
  usz i = 0;
  while (i < wlen && p[i] == want[i]) i++;
  return i != wlen;
}

/* 1 if the trimmed line's first 5 bytes are "GET /". */
static int hq09_is_get_slash(const u8* p, usz n) {
  static const u8 want[5] = {'G', 'E', 'T', ' ', '/'};
  return n >= 5 && !hq09_bytes_differ(p, want, 5);
}

int wired_hq09_parse_get(quic_span line, quic_span* path) {
  usz n = hq09_trim_spaces(line.p, hq09_trim_newlines(line));
  if (!hq09_is_get_slash(line.p, n)) return 0;
  *path = quic_span_of(line.p + 4, n - 4);
  return 1;
}
