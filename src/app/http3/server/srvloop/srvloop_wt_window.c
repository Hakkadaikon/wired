#include "app/http3/server/srvloop/srvloop_impl.h"
#include "common/bytes/util/bits.h"

static usz wt_window_skip_stale(
    const wired_srvloop_wt_window* win, u64 abs_off, usz n);
static u64 wt_window_kept_start(
    const wired_srvloop_wt_window* win, u64 abs_off);
static usz  wt_window_avail_at(u64 lo, usz cap);
static void wt_buf_shift_left(u8* buf, usz cap, usz shift);
static void wt_window_mark(wired_srvloop_wt_window* win, u64 lo, usz n);
static void wt_window_advance(wired_srvloop_wt_window* win);
static void wt_window_reclaim(wired_srvloop_wt_window* win, u8* buf, usz shift);
static int  wt_window_slide_not_due(
    const wired_srvloop_wt_window* win, u64 delivered_to);

/* draft-ietf-webtrans-http3-15 4.3: byte count of [abs_off, abs_off+n) that
 * falls at or past win.base (the stale, already-delivered prefix is
 * excluded) -- 0 if the whole frame is stale. Split out of
 * wired_srvloop_wt_window_accept to keep its own branch count at the gate. */
static usz wt_window_skip_stale(
    const wired_srvloop_wt_window* win, u64 abs_off, usz n) {
  u64 end = abs_off + n;
  if (end <= win->base) {
    return 0;
  }
  return abs_off >= win->base ? n : (usz)(end - win->base);
}

/* The absolute offset the kept (non-stale) portion of [abs_off, abs_off+n)
 * starts at -- abs_off itself once it is already at/past win->base, else
 * win->base (the frame's stale leading bytes are skipped). Split out so the
 * subtraction that follows (relative to win->base) never underflows even
 * when the whole frame is stale (kept == 0). */
static u64 wt_window_kept_start(
    const wired_srvloop_wt_window* win, u64 abs_off) {
  return abs_off > win->base ? abs_off : win->base;
}

/* Byte capacity still open at relative offset lo (cap - lo, or 0 once lo is
 * already at/past cap) -- split out so wired_srvloop_wt_window_accept's own
 * branch count stays at the gate. */
static usz wt_window_avail_at(u64 lo, usz cap) {
  return lo < cap ? cap - (usz)lo : 0;
}

void wired_srvloop_wt_window_accept(
    wired_srvloop_wt_window* win,
    u64                      abs_off,
    usz                      n,
    usz*                     rel_off,
    usz*                     accepted_n) {
  usz kept    = wt_window_skip_stale(win, abs_off, n);
  u64 lo      = wt_window_kept_start(win, abs_off) - win->base;
  usz avail   = wt_window_avail_at(lo, WIRED_SRVLOOP_WT_BUF_CAP);
  *accepted_n = kept < avail ? kept : avail;
  *rel_off    = (usz)lo;
  win->dropped_bytes += kept - *accepted_n;
  wt_window_mark(win, lo, *accepted_n);
}

/* Mark buf[lo, lo + n) received, then move the frontier over every
 * received byte now contiguous with it. */
static void wt_window_mark(wired_srvloop_wt_window* win, u64 lo, usz n) {
  /* a frame past the window (n == 0) must not form a pointer past have[] */
  bits_fill(win->have, (usz)u64_min(lo, WIRED_SRVLOOP_WT_BUF_CAP), n);
  if (n) {
    win->hi = (usz)u64_max(win->hi, lo + n);
  }
  wt_window_advance(win);
}

/* Grow the frontier while the next byte has arrived. Each byte is passed
 * once per window position, so the walk costs nothing per frame. */
static void wt_window_advance(wired_srvloop_wt_window* win) {
  while (win->frontier < WIRED_SRVLOOP_WT_BUF_CAP &&
         bits_get(win->have, win->frontier)) {
    win->frontier++;
  }
}

/* Shift buf's contents left by shift bytes (buf[i] = buf[i+shift]), safe for
 * this specific direction (dst index always < src index, so every byte is
 * read before it could be overwritten). */
static void wt_buf_shift_left(u8* buf, usz cap, usz shift) {
  for (usz i = 0; i + shift < cap; i++) {
    buf[i] = buf[i + shift];
  }
}

/* Drop the delivered prefix [0, shift): the bytes received past it move
 * down and the bitmap shifts with them. Only [0, hi) holds anything, so
 * in-order data (hi == shift, nothing past the prefix) moves no byte and
 * shifts hi / 8 bitmap bytes -- this runs once per delivered frame. hi is
 * taken no lower than the frontier it can never be below. */
static void wt_window_reclaim(
    wired_srvloop_wt_window* win, u8* buf, usz shift) {
  usz hi = (usz)u64_max(win->hi, win->frontier);
  wt_buf_shift_left(buf, hi, shift);
  bits_shift_down(win->have, (hi + 7) / 8 * 8, shift);
  win->hi = hi - shift;
}

/* 1 if delivered_to has not yet consumed the whole current frontier -- slide
 * has nothing to reclaim room for yet. */
static int wt_window_slide_not_due(
    const wired_srvloop_wt_window* win, u64 delivered_to) {
  return delivered_to < win->base + win->frontier;
}

void wired_srvloop_wt_window_slide(
    wired_srvloop_wt_window* win, u8* buf, usz cap, u64 delivered_to) {
  usz shift = win->frontier;
  if (wt_window_slide_not_due(win, delivered_to) || shift == 0) {
    return;
  }
  (void)cap; /* the window never holds more than hi <= cap bytes */
  wt_window_reclaim(win, buf, shift);
  win->base += shift;
  win->frontier = 0;
  wt_window_advance(win);
}
