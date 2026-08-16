#include "common/platform/debug/debug.h"

/* Little-endian decimal digits of v into tmp (at least `width`, zero-padded).
 * Returns the digit count. */
static usz fmt_digits(char tmp[20], u64 v, usz width) {
  usz k = 0;
  do {
    tmp[k++] = (char)('0' + (v % 10));
    v /= 10;
  } while (v);
  while (k < width) tmp[k++] = '0';
  return k;
}

void wired_fmt_u64(char* out, usz* at, const wired_fmt_u64_in* in) {
  char tmp[20];
  usz  k = fmt_digits(tmp, in->v, in->width);
  while (k) out[(*at)++] = tmp[--k];
}

void wired_log_str(const char* s) {
  usz n = 0;
  while (s[n]) n++;
  wired_arch_write(2, s, n);
}

void wired_log_ts(const char* s) {
  i64  ts[2] = {0, 0};
  char p[24];
  usz  at = 0;
  wired_arch_clock_gettime(0, ts);
  wired_fmt_u64(p, &at, &(wired_fmt_u64_in){(u64)ts[0], 1});
  p[at++] = '.';
  wired_fmt_u64(p, &at, &(wired_fmt_u64_in){(u64)ts[1], 9});
  p[at++] = ' ';
  wired_arch_write(2, p, at);
  wired_log_str(s);
}
