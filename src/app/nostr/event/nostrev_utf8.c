#include "app/nostr/event/nostrev_impl.h"

/* Well-formed UTF-8 lead bytes and the range of the byte after them
 * (Unicode 15 Table 3-7; RFC 3629 4): excludes overlongs (C0, C1, E0 80-9F,
 * F0 80-8F), surrogates (ED A0-BF) and > U+10FFFF (F4 90+, F5-FF). */
typedef struct {
  u8 lo, hi, len, c1lo, c1hi;
} nostrev_u8row;

static const nostrev_u8row nostrev_u8rows[] = {
    {0xc2, 0xdf, 2, 0x80, 0xbf}, {0xe0, 0xe0, 3, 0xa0, 0xbf},
    {0xe1, 0xec, 3, 0x80, 0xbf}, {0xed, 0xed, 3, 0x80, 0x9f},
    {0xee, 0xef, 3, 0x80, 0xbf}, {0xf0, 0xf0, 4, 0x90, 0xbf},
    {0xf1, 0xf3, 4, 0x80, 0xbf}, {0xf4, 0xf4, 4, 0x80, 0x8f},
};

static int                  nostrev_in(u8 c, u8 lo, u8 hi);
static const nostrev_u8row* nostrev_u8row_of(u8 lead);
static int nostrev_u8_fits(const nostrev_lx* lx, const nostrev_u8row* r);
static int nostrev_u8_cont(const u8* p, const nostrev_u8row* r);

static int nostrev_in(u8 c, u8 lo, u8 hi) { return (u8)(c - lo) <= hi - lo; }

static const nostrev_u8row* nostrev_u8row_of(u8 lead) {
  for (usz k = 0; k < sizeof(nostrev_u8rows) / sizeof(nostrev_u8rows[0]); k++) {
    if (nostrev_in(lead, nostrev_u8rows[k].lo, nostrev_u8rows[k].hi)) {
      return &nostrev_u8rows[k];
    }
  }
  return 0;
}

static int nostrev_u8_fits(const nostrev_lx* lx, const nostrev_u8row* r) {
  return r && lx->n - lx->i >= r->len;
}

static int nostrev_u8_cont(const u8* p, const nostrev_u8row* r) {
  int ok = nostrev_in(p[1], r->c1lo, r->c1hi);
  for (usz k = 2; k < r->len; k++) {
    ok &= nostrev_in(p[k], 0x80, 0xbf);
  }
  return ok;
}

int nostrev_utf8_seq(nostrev_lx* lx) {
  const nostrev_u8row* r = nostrev_u8row_of(lx->s[lx->i]);
  if (!nostrev_u8_fits(lx, r) || !nostrev_u8_cont(lx->s + lx->i, r)) {
    return 0;
  }
  lx->i += r->len;
  return nostrev_out(lx, lx->s + lx->i - r->len, r->len);
}

/* RFC 3629 3: 1-4 bytes; continuation bytes carry 6 bits each. */
int nostrev_put_cp(nostrev_lx* lx, u32 cp) {
  static const u8 lead[5] = {0, 0, 0xc0, 0xe0, 0xf0};
  u8              b[4];
  usz             n = 1 + (cp >= 0x80) + (cp >= 0x800) + (cp >= 0x10000);
  for (usz k = n; k-- > 1;) {
    b[k] = (u8)(0x80 | (cp & 0x3f));
    cp >>= 6;
  }
  b[0] = (u8)(lead[n] | cp);
  return nostrev_out(lx, b, n);
}
