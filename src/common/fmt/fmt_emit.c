#include "common/fmt/fmt_impl.h"

static usz  fmt_dec_body(char* b, fmt_fparts* r, int prec, int dot);
static int  fmt_fprec(const fmt_spec* sp);
static void fmt_emit_dec(fmt_sink* s, const fmt_spec* sp, u64 bits, int neg);
static void fmt_emit_special(fmt_sink* s, const fmt_spec* sp, u64 bits, int n);
static void fmt_h_f(fmt_sink* s, const fmt_spec* sp, wired_va_list ap);

/* b[0] is a reserved '0'; returns the index of the last body char. */
static usz fmt_dec_body(char* b, fmt_fparts* r, int prec, int dot) {
  usz e = fmt_ip_digits(b, r->ip);
  b[e]  = '.';
  e += (usz)(prec > 0 || dot);
  for (int i = 0; i < prec; i++) {
    r->f *= 10;
    b[e++] = (char)('0' + (r->f >> r->s));
    r->f &= ((u64)1 << r->s) - 1;
  }
  return e - 1;
}

static int fmt_fprec(const fmt_spec* sp) {
  int p = sp->prec < 0 ? 6 : sp->prec;
  return p > 40 ? 40 : p;
}

static void fmt_emit_dec(fmt_sink* s, const fmt_spec* sp, u64 bits, int neg) {
  char       b[80];
  char       pre[3];
  fmt_fparts r;
  fmt_piece  pc = {.pre = pre};
  usz        end;
  fmt_split(&r, bits);
  b[0] = '0';
  end  = fmt_dec_body(b, &r, fmt_fprec(sp), (sp->flags & FMT_HASH) != 0);
  if (fmt_round_up(&r, b[end])) {
    fmt_carry(b, end);
  }
  pc.body    = b + (b[0] == '0');
  pc.bodylen = end + 1 - (usz)(pc.body - b);
  pc.prelen  = (usz)(pre[0] = fmt_sign(sp, neg)) != 0;
  pc.zpad    = (sp->flags & FMT_ZERO) != 0;
  fmt_field(s, sp, &pc);
}

static void fmt_emit_special(fmt_sink* s, const fmt_spec* sp, u64 bits, int n) {
  char      pre[3];
  fmt_piece pc = {.pre = pre, .bodylen = 3};
  pc.body      = (bits << 12) ? "nan" : "inf";
  pc.prelen    = (usz)(pre[0] = fmt_sign(sp, n)) != 0;
  fmt_field(s, sp, &pc);
}

static void fmt_h_f(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  union {
    double d;
    u64    u;
  } x      = {wired_va_arg(ap, double)};
  int neg  = (int)(x.u >> 63);
  u64 bits = x.u & ~((u64)1 << 63);
  if (((bits >> 52) & 0x7ff) == 0x7ff) {
    fmt_emit_special(s, sp, bits, neg);
    return;
  }
  fmt_emit_dec(s, sp, bits, neg);
}

const fmt_handler fmt_tab[128] = {
    ['d'] = fmt_h_d,   ['i'] = fmt_h_d, ['u'] = fmt_h_u,   ['x'] = fmt_h_x,
    ['X'] = fmt_h_x,   ['p'] = fmt_h_p, ['s'] = fmt_h_s,   ['c'] = fmt_h_c,
    ['%'] = fmt_h_pct, ['f'] = fmt_h_f, ['H'] = fmt_h_hex,
};
