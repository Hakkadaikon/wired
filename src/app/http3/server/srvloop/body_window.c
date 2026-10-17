#include "app/http3/server/srvloop/body_window_impl.h"

static int  bodywin_bit(const bodywin* w, usz i);
static void bodywin_set(bodywin* w, usz i, int v);
static int  bodywin_in(const bodywin* w, u64 off);
static void bodywin_put(bodywin* w, u8* buf, u64 off, u8 v);
static int  bodywin_bit_at(const bodywin* w, usz i);

static int bodywin_bit(const bodywin* w, usz i) {
  return (w->have[i / 8] >> (i % 8)) & 1;
}

static void bodywin_set(bodywin* w, usz i, int v) {
  w->have[i / 8] = (u8)((w->have[i / 8] & ~(1u << (i % 8))) | (v << (i % 8)));
}

/* RFC 9000 2.2: the received byte at stream offset off is kept only inside
 * [base, base + BODYWIN_CAP) -- the credit never reaches past it. */
static int bodywin_in(const bodywin* w, u64 off) {
  return off >= w->base && off - w->base < BODYWIN_CAP;
}

static void bodywin_put(bodywin* w, u8* buf, u64 off, u8 v) {
  if (!bodywin_in(w, off)) {
    return;
  }
  buf[off - w->base] = v;
  bodywin_set(w, (usz)(off - w->base), 1);
}

void bodywin_land(bodywin* w, u8* buf, u64 off, wired_span data, int fin) {
  for (usz i = 0; i < data.n; i++) {
    bodywin_put(w, buf, off + i, data.p[i]);
  }
  if (fin) {
    w->fin_off = off + data.n;
  }
  w->fin |= (u8)(fin != 0);
}

usz bodywin_frontier(const bodywin* w) {
  usz n = 0;
  while (n < BODYWIN_CAP && bodywin_bit(w, n)) {
    n++;
  }
  return n;
}

/* have[] bit i, 0 past the window. */
static int bodywin_bit_at(const bodywin* w, usz i) {
  return i < BODYWIN_CAP ? bodywin_bit(w, i) : 0;
}

void bodywin_consume(bodywin* w, u8* buf, usz n) {
  for (usz i = 0; i + n < BODYWIN_CAP; i++) {
    buf[i] = buf[i + n];
  }
  for (usz i = 0; i < BODYWIN_CAP; i++) {
    bodywin_set(w, i, bodywin_bit_at(w, i + n));
  }
  w->base += n;
}
