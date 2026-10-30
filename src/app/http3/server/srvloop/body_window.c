#include "app/http3/server/srvloop/body_window_impl.h"
#include "common/bytes/util/bits.h"

static int  bodywin_in(const bodywin* w, u64 off);
static int  bodywin_fresh(const bodywin* w, u64 off);
static void bodywin_put(bodywin* w, u8* buf, u64 off, u8 v);

/* RFC 9000 2.2: the received byte at stream offset off is kept only inside
 * [base, base + BODYWIN_CAP) -- the credit never reaches past it. */
static int bodywin_in(const bodywin* w, u64 off) {
  return off >= w->base && off - w->base < BODYWIN_CAP;
}

/* RFC 9000 2.2: data at an offset "MUST NOT change if it is sent multiple
 * times", so the first copy of a byte is kept: a decoded request's body
 * views into buf, and a retransmission must not rewrite it underneath. */
static int bodywin_fresh(const bodywin* w, u64 off) {
  return bodywin_in(w, off) && !bits_get(w->have, (usz)(off - w->base));
}

static void bodywin_put(bodywin* w, u8* buf, u64 off, u8 v) {
  if (!bodywin_fresh(w, off)) {
    return;
  }
  buf[off - w->base] = v;
  bits_set(w->have, (usz)(off - w->base), 1);
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
  while (n < BODYWIN_CAP && bits_get(w->have, n)) {
    n++;
  }
  return n;
}

int bodywin_fin_gap(const bodywin* w) {
  return w->fin && w->base + bodywin_frontier(w) < w->fin_off;
}

void bodywin_consume(bodywin* w, u8* buf, usz n) {
  for (usz i = 0; i + n < BODYWIN_CAP; i++) {
    buf[i] = buf[i + n];
  }
  bits_shift_down(w->have, BODYWIN_CAP, n);
  w->base += n;
}
