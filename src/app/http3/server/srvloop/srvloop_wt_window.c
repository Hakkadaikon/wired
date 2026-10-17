#include "app/http3/server/srvloop/srvloop_impl.h"

static u64 wt_window_kept_start(
    const wired_srvloop_wt_window* win, u64 abs_off);
static usz  wt_window_avail_at(u64 lo, usz cap);
static void wt_buf_shift_left(u8* buf, usz cap, usz shift);
static void wt_range_rebase_one(wired_srvloop_wt_window* win, usz i, usz shift);
static void wt_ranges_rebase(wired_srvloop_wt_window* win, usz shift);
static int  wt_window_slide_not_due(
    const wired_srvloop_wt_window* win, u64 delivered_to);

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
  usz kept    = srvloop_wt_window_skip_stale(win, abs_off, n);
  u64 lo      = wt_window_kept_start(win, abs_off) - win->base;
  usz avail   = wt_window_avail_at(lo, WIRED_SRVLOOP_WT_BUF_CAP);
  *accepted_n = kept < avail ? kept : avail;
  *rel_off    = (usz)lo;
  win->dropped_bytes += kept - *accepted_n;
  if (*accepted_n) {
    srvloop_wt_window_insert(win, lo, lo + *accepted_n);
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

/* Rebase one range by shift, clipping its lo to 0 rather than underflowing
 * when the range started before shift (only ranges[0], the frontier's own
 * range, can start below shift -- ranges are sorted and shift is exactly
 * ranges[0].hi, so ranges[0].lo is always 0). Ranges entirely below shift
 * were already dropped by the caller before this runs. */
static void wt_range_rebase_one(
    wired_srvloop_wt_window* win, usz i, usz shift) {
  win->range_lo[i] = win->range_lo[i] > shift ? win->range_lo[i] - shift : 0;
  win->range_hi[i] -= shift;
}

/* Rebase win's range set by shift (win->base is moving forward by the same
 * amount): drop every range entirely consumed by the slide (range_hi <=
 * shift -- this is always at least ranges[0], the frontier's own range) and
 * rebase every surviving one, keeping only what is still ahead of the new
 * base. */
static void wt_ranges_rebase(wired_srvloop_wt_window* win, usz shift) {
  usz out = 0;
  for (usz i = 0; i < win->range_n; i++) {
    if (win->range_hi[i] <= shift) {
      continue;
    }
    wt_range_rebase_one(win, i, shift);
    win->range_lo[out] = win->range_lo[i];
    win->range_hi[out] = win->range_hi[i];
    out++;
  }
  win->range_n = out;
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
  wt_buf_shift_left(buf, cap, shift);
  win->base += shift;
  wt_ranges_rebase(win, shift);
  srvloop_wt_window_recompute_frontier(win);
}
