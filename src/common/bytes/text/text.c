#include "common/bytes/text/text.h"

#include "common/arch/sysops.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

/* Length of the common prefix of a[0..n) and b[0..n). */
static usz text_common(const u8* a, const u8* b, usz n) {
  usz i = 0;
  while (i < n && a[i] == b[i]) i++;
  return i;
}

int wired_span_eq(wired_span a, wired_span b) {
  return a.n == b.n && text_common(a.p, b.p, a.n) == a.n;
}

int wired_span_eq_cstr(wired_span s, const char* lit) {
  usz n = wired_cstr_len(lit);
  return s.n == n && text_common(s.p, (const u8*)lit, n) == n;
}

ssz wired_span_find(wired_span s, u8 c) {
  for (usz i = 0; i < s.n; i++)
    if (s.p[i] == c) return (ssz)i;
  return -1;
}

usz wired_span_to_cstr(char* out, usz cap, wired_span s) {
  if (cap == 0) return 0;
  usz n = (usz)u64_min(s.n, cap - 1);
  for (usz i = 0; i < n; i++) out[i] = (char)s.p[i];
  out[n] = 0;
  return n;
}

usz wired_hex_encode(char* out, usz cap, wired_span s) {
  static const char digits[] = "0123456789abcdef";
  if (cap == 0) return 0;
  usz n = (usz)u64_min(s.n, (cap - 1) / 2);
  for (usz i = 0; i < n; i++) {
    out[2 * i]     = digits[s.p[i] >> 4];
    out[2 * i + 1] = digits[s.p[i] & 15];
  }
  out[2 * n] = 0;
  return 2 * n;
}

/* Bytes hexed per write: 2 * TEXT_HEX_CHUNK + 1 characters of stack. */
#define TEXT_HEX_CHUNK 128

static void text_write_all(i64 fd, const u8* p, usz n) {
  usz done = 0;
  while (done < n) {
    i64 r = wired_arch_write(fd, p + done, (i64)(n - done));
    if (r <= 0) return;
    done += (usz)r;
  }
}

void wired_dump_hex(i64 fd, wired_span s) {
  char line[2 * TEXT_HEX_CHUNK + 1];
  for (usz at = 0; at < s.n; at += TEXT_HEX_CHUNK) {
    usz n = (usz)u64_min(s.n - at, TEXT_HEX_CHUNK);
    usz w = wired_hex_encode(line, sizeof line, wired_span_of(s.p + at, n));
    text_write_all(fd, (const u8*)line, w);
  }
}

void wired_dump_text(i64 fd, wired_span s) { text_write_all(fd, s.p, s.n); }

int wired_cstr_eq(const char* a, const char* b) {
  return wired_span_eq_cstr(wired_span_cstr(a), b);
}

usz wired_cstr_append(char* dst, usz cap, usz at, wired_span s) {
  if (at >= cap) return at; /* full (or cap 0): nothing fits, not even NUL */
  usz n = (usz)u64_min(s.n, cap - 1 - at);
  for (usz i = 0; i < n; i++) dst[at + i] = (char)s.p[i];
  dst[at + n] = 0;
  return at + n;
}

wired_span wired_span_strip_lead(wired_span s, u8 c) {
  usz k = s.n > 0 && s.p[0] == c;
  return wired_span_of(s.p + k, s.n - k);
}

usz wired_obuf_put(wired_obuf* b, wired_span s) {
  usz n = (usz)u64_min(s.n, b->cap - b->len);
  for (usz i = 0; i < n; i++) b->p[b->len + i] = s.p[i];
  b->len += n;
  return n;
}
