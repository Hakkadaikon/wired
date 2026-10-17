#include "common/fmt/fmt_impl.h"

static int         fmt_idx(const char* set, char c);
static const char* fmt_flags(const char* p, fmt_spec* sp);
static const char* fmt_num(const char* p, int* out);
static const char* fmt_width(const char* p, fmt_spec* sp, wired_va_list ap);
static const char* fmt_prec(const char* p, fmt_spec* sp, wired_va_list ap);
static const char* fmt_len(const char* p, fmt_spec* sp);
static const char* fmt_spec_parse(
    const char* p, fmt_spec* sp, wired_va_list ap);
static fmt_handler fmt_lookup(char c);
static const char* fmt_directive(fmt_sink* s, const char* p, wired_va_list ap);

/* ---- spec parsing ---- */

static int fmt_idx(const char* set, char c) {
  for (int i = 0; set[i]; i++)
    if (set[i] == c) return i;
  return -1;
}

static const char* fmt_flags(const char* p, fmt_spec* sp) {
  int i;
  while ((i = fmt_idx("-0+ #", *p)) >= 0) {
    sp->flags |= 1u << i;
    p++;
  }
  return p;
}

static const char* fmt_num(const char* p, int* out) {
  int v = 0;
  while (*p >= '0' && *p <= '9') v = v * 10 + (*p++ - '0');
  *out = v;
  return p;
}

static const char* fmt_width(const char* p, fmt_spec* sp, wired_va_list ap) {
  if (*p != '*') return fmt_num(p, &sp->width);
  sp->width = wired_va_arg(ap, int);
  sp->flags |= FMT_MINUS * (u32)(sp->width < 0);
  sp->width = sp->width < 0 ? -sp->width : sp->width;
  return p + 1;
}

static const char* fmt_prec(const char* p, fmt_spec* sp, wired_va_list ap) {
  if (*p != '.') return p;
  if (p[1] != '*') return fmt_num(p + 1, &sp->prec);
  sp->prec = wired_va_arg(ap, int);
  return p + 2;
}

/* len transitions: row = letter (h, l, z), column = current length. */
static const u8 fmt_len_next[3][6] = {
    {FMT_LEN_H, FMT_LEN_HH, FMT_LEN_HH, FMT_LEN_H, FMT_LEN_H, FMT_LEN_H},
    {FMT_LEN_L, FMT_LEN_L, FMT_LEN_L, FMT_LEN_LL, FMT_LEN_LL, FMT_LEN_L},
    {FMT_LEN_Z, FMT_LEN_Z, FMT_LEN_Z, FMT_LEN_Z, FMT_LEN_Z, FMT_LEN_Z},
};

static const char* fmt_len(const char* p, fmt_spec* sp) {
  int i;
  while ((i = fmt_idx("hlz", *p)) >= 0) {
    sp->len = fmt_len_next[i][sp->len];
    p++;
  }
  return p;
}

static const char* fmt_spec_parse(
    const char* p, fmt_spec* sp, wired_va_list ap) {
  *sp      = (fmt_spec){0, 0, -1, FMT_LEN_INT, 0};
  p        = fmt_flags(p, sp);
  p        = fmt_width(p, sp, ap);
  p        = fmt_prec(p, sp, ap);
  p        = fmt_len(p, sp);
  sp->conv = *p;
  return p;
}

static fmt_handler fmt_lookup(char c) {
  return (u8)c < 128 ? fmt_tab[(u8)c] : 0;
}

/* One directive, `p` just after the '%'; returns the next input pointer. */
static const char* fmt_directive(fmt_sink* s, const char* p, wired_va_list ap) {
  fmt_spec    sp;
  fmt_handler h;
  p = fmt_spec_parse(p, &sp, ap);
  h = fmt_lookup(sp.conv);
  if (!h) {
    fmt_put(s, '%');
    return p;
  }
  h(s, &sp, ap);
  return p + 1;
}

void fmt_run(fmt_sink* s, const char* fmt, wired_va_list ap) {
  while (*fmt) {
    if (*fmt != '%') {
      fmt_put(s, *fmt++);
      continue;
    }
    fmt = fmt_directive(s, fmt + 1, ap);
  }
}
