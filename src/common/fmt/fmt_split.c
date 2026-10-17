#include "common/fmt/fmt_impl.h"

static void fmt_split_frac(fmt_fparts* r, u64 mant, int ex);
static u64  fmt_mant(u64 bits, u64 e);
static char fmt_carry_fix(char c);

void fmt_h_s(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  const char* p  = wired_va_arg(ap, const char*);
  fmt_piece   pc = {.pre = 0};
  pc.body        = p ? p : "(null)";
  pc.bodylen     = fmt_nlen(pc.body, sp->prec < 0 ? ~(usz)0 : (usz)sp->prec);
  fmt_field(s, sp, &pc);
}

void fmt_h_c(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  char      c  = (char)wired_va_arg(ap, int);
  fmt_piece pc = {.body = &c, .bodylen = 1};
  fmt_field(s, sp, &pc);
}

void fmt_h_pct(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  (void)sp;
  (void)ap;
  fmt_put(s, '%');
}

static void fmt_split_frac(fmt_fparts* r, u64 mant, int ex) {
  u32 s    = (u32)-ex;
  u32 drop = s > 60 ? s - 60 : 0;
  mant     = drop >= 64 ? 0 : mant >> drop;
  r->s     = s - drop;
  r->ip    = mant >> r->s;
  r->f     = mant & (((u64)1 << r->s) - 1);
}

/* IEEE-754 binary64 significand with the implicit bit for exponent field e. */
static u64 fmt_mant(u64 bits, u64 e) {
  return (bits & (((u64)1 << 52) - 1)) | ((u64)(e != 0) << 52);
}

void fmt_split(fmt_fparts* r, u64 bits) {
  u64 e    = (bits >> 52) & 0x7ff;
  u64 mant = fmt_mant(bits, e);
  int ex   = (int)(e + (e == 0)) - 1075;
  *r       = (fmt_fparts){0, 0, 0};
  if (ex < 0) {
    fmt_split_frac(r, mant, ex);
    return;
  }
  r->ip = ex > 11 ? ~(u64)0 : mant << ex;
}

int fmt_round_up(const fmt_fparts* r, char last) {
  u64 half = (u64)1 << r->s;
  u64 t    = r->f << 1;
  return t > half || (t == half && ((last - '0') & 1));
}

static char fmt_carry_fix(char c) { return c == '.' ? c : '0'; }

void fmt_carry(char* b, usz end) {
  usz i = end;
  while (b[i] == '9' || b[i] == '.') {
    b[i] = fmt_carry_fix(b[i]);
    i--;
  }
  b[i]++;
}

/* Integer digits of ip into b[1..]; returns the next write index. */
usz fmt_ip_digits(char* b, u64 v) {
  char tmp[20];
  usz  k = 0;
  usz  e = 1;
  do {
    tmp[k++] = (char)('0' + v % 10);
    v /= 10;
  } while (v);
  while (k) {
    b[e++] = tmp[--k];
  }
  return e;
}
