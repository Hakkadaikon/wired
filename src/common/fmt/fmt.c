#include "common/fmt/fmt.h"

#include "common/arch/sysops.h"

/* Flag bits, in the order of the "-0+ #" flag characters. */
#define FMT_MINUS 1u
#define FMT_ZERO 2u
#define FMT_PLUS 4u
#define FMT_SPACE 8u
#define FMT_HASH 16u

enum { FMT_LEN_INT, FMT_LEN_H, FMT_LEN_HH, FMT_LEN_L, FMT_LEN_LL, FMT_LEN_Z };

typedef struct {
  char* out;
  usz   cap;
  usz   n;
} fmt_sink;

typedef struct {
  u32  flags;
  int  width;
  int  prec; /* -1: absent */
  int  len;
  char conv;
} fmt_spec;

/* One conversion's output: prefix, precision zeros, body. */
typedef struct {
  const char* pre;
  usz         prelen;
  usz         zeros;
  const char* body;
  usz         bodylen;
  int         zpad; /* pad with zeros instead of spaces (ignored with '-') */
} fmt_piece;

typedef void (*fmt_handler)(fmt_sink*, const fmt_spec*, wired_va_list);

static void fmt_put(fmt_sink* s, char c) {
  if (s->n + 1 < s->cap) s->out[s->n] = c;
  s->n++;
}

static void fmt_rep(fmt_sink* s, char c, usz count) {
  for (usz i = 0; i < count; i++) fmt_put(s, c);
}

static void fmt_bytes(fmt_sink* s, const char* p, usz n) {
  for (usz i = 0; i < n; i++) fmt_put(s, p[i]);
}

static void fmt_field(fmt_sink* s, const fmt_spec* sp, const fmt_piece* pc) {
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
  return (flags & FMT_PLUS) ? '+' : (flags & FMT_SPACE) ? ' ' : 0;
}

static char fmt_sign(const fmt_spec* sp, int neg) {
  if (neg) return '-';
  return fmt_sign_flag(sp->flags);
}

/* ---- integers ---- */

typedef struct {
  u64 v;
  int neg;
  u32 base;
  int upper;
  int hash; /* always emit the 0x prefix (%p); else only '#' and v != 0 */
} fmt_int;

static const u8 fmt_len_bits[] = {32, 16, 8, 64, 64, 64};

static u64 fmt_get(const fmt_spec* sp, wired_va_list ap, int sgn) {
  u64 v     = sp->len >= FMT_LEN_L ? wired_va_arg(ap, u64)
                                   : (u64)wired_va_arg(ap, unsigned);
  u32 shift = 64u - fmt_len_bits[sp->len];
  v <<= shift;
  return sgn ? (u64)((i64)v >> shift) : v >> shift;
}

/* Little-endian digits; zero prints one '0' unless the precision is 0. */
static usz fmt_idigits(char* tmp, const fmt_spec* sp, const fmt_int* a) {
  static const char dig[] = "0123456789abcdef0123456789ABCDEF";
  usz               k     = 0;
  u64               v     = a->v;
  do {
    tmp[k++] = dig[(v % a->base) + 16u * (u32)(a->upper != 0)];
    v /= a->base;
  } while (v);
  return k - (usz)(a->v == 0 && sp->prec == 0);
}

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
  for (usz i = 0; i < k; i++) dst[i] = src[k - 1 - i];
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

static void fmt_h_d(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  u64     v = fmt_get(sp, ap, 1);
  int     n = (i64)v < 0;
  fmt_int a = {n ? -v : v, n, 10, 0, 0};
  fmt_emit_int(s, sp, &a);
}

static void fmt_h_u(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  fmt_int a = {fmt_get(sp, ap, 0), 0, 10, 0, 0};
  fmt_emit_int(s, sp, &a);
}

static void fmt_h_x(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  fmt_int a = {fmt_get(sp, ap, 0), 0, 16, sp->conv == 'X', 0};
  fmt_emit_int(s, sp, &a);
}

static void fmt_h_p(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  fmt_int a = {(u64)wired_va_arg(ap, void*), 0, 16, 0, 1};
  fmt_emit_int(s, sp, &a);
}

/* ---- strings, chars, percent ---- */

static usz fmt_nlen(const char* p, usz lim) {
  usz n = 0;
  while (n < lim && p[n]) n++;
  return n;
}

static void fmt_h_s(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  const char* p  = wired_va_arg(ap, const char*);
  fmt_piece   pc = {.pre = 0};
  pc.body        = p ? p : "(null)";
  pc.bodylen     = fmt_nlen(pc.body, sp->prec < 0 ? ~(usz)0 : (usz)sp->prec);
  fmt_field(s, sp, &pc);
}

static void fmt_h_c(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  char      c  = (char)wired_va_arg(ap, int);
  fmt_piece pc = {.body = &c, .bodylen = 1};
  fmt_field(s, sp, &pc);
}

static void fmt_h_pct(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  (void)sp;
  (void)ap;
  fmt_put(s, '%');
}

/* ---- %f: exact binary-to-decimal, round half to even ---- */

typedef struct {
  u64 ip;
  u64 f; /* fraction numerator over 2^s */
  u32 s; /* 0..60 */
} fmt_fparts;

static void fmt_split_frac(fmt_fparts* r, u64 mant, int ex) {
  u32 s    = (u32)-ex;
  u32 drop = s > 60 ? s - 60 : 0;
  mant     = drop >= 64 ? 0 : mant >> drop;
  r->s     = s - drop;
  r->ip    = mant >> r->s;
  r->f     = mant & (((u64)1 << r->s) - 1);
}

static void fmt_split(fmt_fparts* r, u64 bits) {
  u64 e    = (bits >> 52) & 0x7ff;
  u64 mant = (bits & (((u64)1 << 52) - 1)) | ((u64)(e != 0) << 52);
  int ex   = (int)(e + (e == 0)) - 1075;
  *r       = (fmt_fparts){0, 0, 0};
  if (ex < 0) {
    fmt_split_frac(r, mant, ex);
    return;
  }
  r->ip = ex > 11 ? ~(u64)0 : mant << ex;
}

static int fmt_round_up(const fmt_fparts* r, char last) {
  u64 half = (u64)1 << r->s;
  u64 t    = r->f << 1;
  return t > half || (t == half && ((last - '0') & 1));
}

static char fmt_carry_fix(char c) { return c == '.' ? c : '0'; }

static void fmt_carry(char* b, usz end) {
  usz i = end;
  while (b[i] == '9' || b[i] == '.') {
    b[i] = fmt_carry_fix(b[i]);
    i--;
  }
  b[i]++;
}

/* Integer digits of ip into b[1..]; returns the next write index. */
static usz fmt_ip_digits(char* b, u64 v) {
  char tmp[20];
  usz  k = 0;
  usz  e = 1;
  do {
    tmp[k++] = (char)('0' + v % 10);
    v /= 10;
  } while (v);
  while (k) b[e++] = tmp[--k];
  return e;
}

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
  if (fmt_round_up(&r, b[end])) fmt_carry(b, end);
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

static const fmt_handler fmt_tab[128] = {
    ['d'] = fmt_h_d,   ['i'] = fmt_h_d, ['u'] = fmt_h_u, ['x'] = fmt_h_x,
    ['X'] = fmt_h_x,   ['p'] = fmt_h_p, ['s'] = fmt_h_s, ['c'] = fmt_h_c,
    ['%'] = fmt_h_pct, ['f'] = fmt_h_f,
};

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

static void fmt_run(fmt_sink* s, const char* fmt, wired_va_list ap) {
  while (*fmt) {
    if (*fmt != '%') {
      fmt_put(s, *fmt++);
      continue;
    }
    fmt = fmt_directive(s, fmt + 1, ap);
  }
}

usz wired_vsnprintf(char* out, usz cap, const char* fmt, wired_va_list ap) {
  fmt_sink s = {out, cap, 0};
  fmt_run(&s, fmt, ap);
  if (cap) out[s.n < cap ? s.n : cap - 1] = 0;
  return s.n;
}

usz wired_snprintf(char* out, usz cap, const char* fmt, ...) {
  wired_va_list ap;
  usz           n;
  wired_va_start(ap, fmt);
  n = wired_vsnprintf(out, cap, fmt, ap);
  wired_va_end(ap);
  return n;
}

usz wired_obuf_printf(wired_obuf* b, const char* fmt, ...) {
  usz           room = b->cap - b->len;
  wired_va_list ap;
  if (room == 0) return 0;
  wired_va_start(ap, fmt);
  usz n = wired_vsnprintf((char*)b->p + b->len, room, fmt, ap);
  wired_va_end(ap);
  n = n < room ? n : room - 1;
  b->len += n;
  return n;
}

static i64 fmt_write_all(i64 fd, const char* buf, usz n) {
  usz done = 0;
  while (done < n) {
    i64 r = wired_arch_write(fd, buf + done, (i64)(n - done));
    if (r <= 0) return r;
    done += (usz)r;
  }
  return (i64)n;
}

ssz wired_dprintf(i64 fd, const char* fmt, ...) {
  char          buf[512];
  wired_va_list ap;
  usz           n;
  wired_va_start(ap, fmt);
  n = wired_vsnprintf(buf, sizeof buf, fmt, ap);
  wired_va_end(ap);
  return fmt_write_all(fd, buf, n < sizeof buf ? n : sizeof buf - 1);
}
