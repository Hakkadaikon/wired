#include "tls/ext/salpn/punycode.h"

/* RFC 3492 5: the Bootstring parameter values for Punycode. */
#define PUNY_BASE 36u
#define PUNY_TMIN 1u
#define PUNY_TMAX 26u
#define PUNY_SKEW 38u
#define PUNY_DAMP 700u
#define PUNY_INITIAL_BIAS 72u
#define PUNY_INITIAL_N 128u

/* RFC 3492 6.3 encoder state. */
typedef struct {
  const u32* cp;
  usz        n;
  u8*        out;
  usz        cap;
  usz        len;
  int        ok;   /* 0 once out overflowed */
  u32        code; /* the "n" of 6.3: next code point to insert */
  u32        delta;
  u32        bias;
  usz        h; /* code points handled so far */
  usz        b; /* basic code points */
} puny;

static void puny_put(puny* p, u8 c) {
  if (p->len >= p->cap) {
    p->ok = 0;
    return;
  }
  p->out[p->len++] = c;
}

/* RFC 3492 5: digit values 0..25 are a..z, 26..35 are 0..9. */
static u8 puny_digit(u32 d) { return (u8)(d < 26 ? 'a' + d : '0' + d - 26); }

/* RFC 3492 6.3: the threshold t for position k. */
static u32 puny_t(u32 k, u32 bias) {
  if (k <= bias) {
    return PUNY_TMIN;
  }
  return k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias;
}

/* RFC 3492 6.1: bias adaptation after each delta. */
static u32 puny_adapt(u32 delta, usz numpoints, int first) {
  u32 k = 0;
  delta = first ? delta / PUNY_DAMP : delta / 2;
  delta += delta / (u32)numpoints;
  while (delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2) {
    delta /= PUNY_BASE - PUNY_TMIN;
    k += PUNY_BASE;
  }
  return k + (PUNY_BASE - PUNY_TMIN + 1) * delta / (delta + PUNY_SKEW);
}

/* RFC 3492 6.3: q as a generalized variable-length integer. */
static void puny_put_int(puny* p, u32 q) {
  for (u32 k = PUNY_BASE;; k += PUNY_BASE) {
    u32 t = puny_t(k, p->bias);
    if (q < t) {
      break;
    }
    puny_put(p, puny_digit(t + (q - t) % (PUNY_BASE - t)));
    q = (q - t) / (PUNY_BASE - t);
  }
  puny_put(p, puny_digit(q));
}

static void puny_put_basic(puny* p, u32 c) {
  if (c < 0x80) {
    puny_put(p, (u8)c);
    p->b++;
  }
}

/* The basic code points in order, then the delimiter when there were any. */
static void puny_basics(puny* p) {
  for (usz i = 0; i < p->n; i++) {
    puny_put_basic(p, p->cp[i]);
  }
  p->h = p->b;
  if (p->b > 0) {
    puny_put(p, '-');
  }
}

static u32 puny_min_ge(u32 m, u32 c, u32 floor) {
  return c >= floor && c < m ? c : m;
}

/* The smallest code point >= p->code still to insert. */
static u32 puny_next_min(const puny* p) {
  u32 m = 0xFFFFFFFFu;
  for (usz i = 0; i < p->n; i++) {
    m = puny_min_ge(m, p->cp[i], p->code);
  }
  return m;
}

/* One input code point of the RFC 3492 6.3 inner loop. */
static void puny_step(puny* p, u32 c) {
  if (c < p->code) {
    p->delta++;
    return;
  }
  if (c == p->code) {
    puny_put_int(p, p->delta);
    p->bias  = puny_adapt(p->delta, p->h + 1, p->h == p->b);
    p->delta = 0;
    p->h++;
  }
}

/* One pass of the RFC 3492 6.3 outer loop: insert every copy of the next
 * code point. */
static void puny_round(puny* p) {
  u32 m = puny_next_min(p);
  p->delta += (m - p->code) * (u32)(p->h + 1);
  p->code = m;
  for (usz i = 0; i < p->n; i++) {
    puny_step(p, p->cp[i]);
  }
  p->delta++;
  p->code++;
}

static int puny_more(const puny* p) { return p->ok && p->h < p->n; }

usz salpn_punycode_encode(const u32* cp, usz n, u8* out, usz cap) {
  puny p = {cp, n, out, cap, 0, 1, PUNY_INITIAL_N, 0, PUNY_INITIAL_BIAS, 0, 0};
  puny_basics(&p);
  while (puny_more(&p)) {
    puny_round(&p);
  }
  return p.ok ? p.len : 0;
}
