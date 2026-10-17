#include "common/fmt/fmt_impl.h"

static int  fmt_hash_hex(const fmt_spec* sp, const fmt_int* a);
static int  fmt_has_0x(const fmt_spec* sp, const fmt_int* a);
static usz  fmt_int_pre(char pre[3], const fmt_spec* sp, const fmt_int* a);
static void fmt_rev(char* dst, const char* src, usz k);
static void fmt_emit_int(fmt_sink* s, const fmt_spec* sp, const fmt_int* a);

static int fmt_hash_hex(const fmt_spec* sp, const fmt_int* a) {
  return (sp->flags & FMT_HASH) && a->v != 0 && a->base == 16;
}

static int fmt_has_0x(const fmt_spec* sp, const fmt_int* a) {
  return a->hash || fmt_hash_hex(sp, a);
}

static usz fmt_int_pre(char pre[3], const fmt_spec* sp, const fmt_int* a) {
  char c = fmt_sign(sp, a->neg);
  usz  n = c != 0;
  pre[0] = c;
  if (fmt_has_0x(sp, a)) {
    pre[n++] = '0';
    pre[n++] = a->upper ? 'X' : 'x';
  }
  return n;
}

static void fmt_rev(char* dst, const char* src, usz k) {
  for (usz i = 0; i < k; i++) {
    dst[i] = src[k - 1 - i];
  }
}

static void fmt_emit_int(fmt_sink* s, const fmt_spec* sp, const fmt_int* a) {
  char      pre[3];
  char      tmp[24];
  char      rev[24];
  fmt_piece pc = {.pre = pre};
  usz       k  = fmt_idigits(tmp, sp, a);
  fmt_rev(rev, tmp, k);
  pc.prelen  = fmt_int_pre(pre, sp, a);
  pc.body    = rev;
  pc.bodylen = k;
  pc.zeros   = sp->prec > (int)k ? (usz)(sp->prec - (int)k) : 0;
  pc.zpad    = (sp->flags & FMT_ZERO) && sp->prec < 0;
  fmt_field(s, sp, &pc);
}

void fmt_h_d(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  u64     v = fmt_get(sp, ap, 1);
  int     n = (i64)v < 0;
  fmt_int a = {n ? -v : v, n, 10, 0, 0};
  fmt_emit_int(s, sp, &a);
}

void fmt_h_u(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  fmt_int a = {fmt_get(sp, ap, 0), 0, 10, 0, 0};
  fmt_emit_int(s, sp, &a);
}

void fmt_h_x(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  fmt_int a = {fmt_get(sp, ap, 0), 0, 16, sp->conv == 'X', 0};
  fmt_emit_int(s, sp, &a);
}

void fmt_h_p(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  fmt_int a = {(u64)wired_va_arg(ap, void*), 0, 16, 0, 1};
  fmt_emit_int(s, sp, &a);
}

/* ---- strings, chars, percent ---- */

usz fmt_nlen(const char* p, usz lim) {
  usz n = 0;
  while (n < lim && p[n]) {
    n++;
  }
  return n;
}
