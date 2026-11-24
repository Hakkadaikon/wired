#include "app/nostr/event/nostrev_impl.h"

/* JSON simple escapes (RFC 8259 7) and what they decode to. */
static const u8 nostrev_esc[8][2] = {
    {'"', '"'},  {'\\', '\\'}, {'/', '/'},  {'b', 0x08},
    {'f', 0x0c}, {'n', 0x0a},  {'r', 0x0d}, {'t', 0x09},
};

static int nostrev_esc_simple(nostrev_lx* lx, int e);
static int nostrev_hex4(nostrev_lx* lx, u32* v);
static int nostrev_is_hi(u32 cp);
static int nostrev_is_lo(u32 cp);
static int nostrev_low_follows(nostrev_lx* lx, u32* lo);
static int nostrev_esc_pair(nostrev_lx* lx, u32 hi);
static int nostrev_esc_cp(nostrev_lx* lx, u32 cp);
static int nostrev_esc_u(nostrev_lx* lx);

static int nostrev_esc_simple(nostrev_lx* lx, int e) {
  for (usz k = 0; k < 8; k++) {
    if (nostrev_esc[k][0] == e) {
      return nostrev_out(lx, &nostrev_esc[k][1], 1);
    }
  }
  return 0;
}

static int nostrev_hex4(nostrev_lx* lx, u32* v) {
  int ok  = 1;
  u32 acc = 0;
  if (lx->n - lx->i < 4) {
    return 0;
  }
  for (usz k = 0; k < 4; k++) {
    int h = nostrev_hexval(lx->s[lx->i + k], 0x20);
    ok &= h >= 0;
    acc = acc << 4 | (u32)(h & 15);
  }
  lx->i += 4;
  *v = acc;
  return ok;
}

static int nostrev_is_hi(u32 cp) { return cp - 0xd800 < 0x400; }
static int nostrev_is_lo(u32 cp) { return cp - 0xdc00 < 0x400; }

static int nostrev_low_follows(nostrev_lx* lx, u32* lo) {
  return nostrev_lit(lx, "\\u", 2) && nostrev_hex4(lx, lo) &&
         nostrev_is_lo(*lo);
}

/* RFC 8259 7 / RFC 2781 2.2: a high surrogate must be followed by an
 * escaped low surrogate. */
static int nostrev_esc_pair(nostrev_lx* lx, u32 hi) {
  u32 lo;
  if (!nostrev_low_follows(lx, &lo)) {
    return 0;
  }
  return nostrev_put_cp(lx, 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00));
}

static int nostrev_esc_cp(nostrev_lx* lx, u32 cp) {
  if (nostrev_is_lo(cp)) {
    return 0; /* lone low surrogate */
  }
  if (nostrev_is_hi(cp)) {
    return nostrev_esc_pair(lx, cp);
  }
  return nostrev_put_cp(lx, cp);
}

static int nostrev_esc_u(nostrev_lx* lx) {
  u32 cp;
  if (!nostrev_hex4(lx, &cp)) {
    return 0;
  }
  return nostrev_esc_cp(lx, cp);
}

int nostrev_escape(nostrev_lx* lx) {
  int e;
  lx->i++; /* the backslash */
  e = nostrev_take(lx);
  if (e == 'u') {
    return nostrev_esc_u(lx);
  }
  return nostrev_esc_simple(lx, e);
}
