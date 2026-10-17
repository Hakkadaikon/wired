/* Flag bits, in the order of the "-0+ #" flag characters. */

#include "common/fmt/fmt_impl.h"

static void fmt_rep(fmt_sink* s, char c, usz count);
static void fmt_bytes(fmt_sink* s, const char* p, usz n);
static char fmt_sign_flag(u32 flags);

void fmt_put(fmt_sink* s, char c) {
  if (s->n + 1 < s->cap) {
    s->out[s->n] = c;
  }
  s->n++;
}

static void fmt_rep(fmt_sink* s, char c, usz count) {
  for (usz i = 0; i < count; i++) {
    fmt_put(s, c);
  }
}

static void fmt_bytes(fmt_sink* s, const char* p, usz n) {
  for (usz i = 0; i < n; i++) {
    fmt_put(s, p[i]);
  }
}

void fmt_field(fmt_sink* s, const fmt_spec* sp, const fmt_piece* pc) {
  usz total = pc->prelen + pc->zeros + pc->bodylen;
  usz pad   = (usz)sp->width > total ? (usz)sp->width - total : 0;
  usz zp    = pad * (usz)(pc->zpad && !(sp->flags & FMT_MINUS));
  usz sppad = pad - zp;
  usz left  = sppad * !(sp->flags & FMT_MINUS);
  fmt_rep(s, ' ', left);
  fmt_bytes(s, pc->pre, pc->prelen);
  fmt_rep(s, '0', pc->zeros + zp);
  fmt_bytes(s, pc->body, pc->bodylen);
  fmt_rep(s, ' ', sppad - left);
}

/* ---- sign / prefix ---- */

static char fmt_sign_flag(u32 flags) {
  return (char)((flags & FMT_PLUS) ? '+' : (flags & FMT_SPACE) ? ' ' : 0);
}

char fmt_sign(const fmt_spec* sp, int neg) {
  if (neg) {
    return '-';
  }
  return fmt_sign_flag(sp->flags);
}

static const u8 fmt_len_bits[] = {32, 16, 8, 64, 64, 64};

u64 fmt_get(const fmt_spec* sp, wired_va_list ap, int sgn) {
  u64 v     = sp->len >= FMT_LEN_L ? wired_va_arg(ap, u64)
                                   : (u64)wired_va_arg(ap, unsigned);
  u32 shift = 64u - fmt_len_bits[sp->len];
  v <<= shift;
  return sgn ? (u64)((i64)v >> shift) : v >> shift;
}

/* Little-endian digits; zero prints one '0' unless the precision is 0. */
usz fmt_idigits(char* tmp, const fmt_spec* sp, const fmt_int* a) {
  static const char dig[] = "0123456789abcdef0123456789ABCDEF";
  usz               k     = 0;
  u64               v     = a->v;
  do {
    tmp[k++] = dig[(v % a->base) + (u64)16u * (u32)(a->upper != 0)];
    v /= a->base;
  } while (v);
  return k - (usz)(a->v == 0 && sp->prec == 0);
}
