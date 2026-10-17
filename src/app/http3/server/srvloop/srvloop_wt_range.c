#include "app/http3/server/srvloop/srvloop_impl.h"

static int wt_ranges_touches_prev(
    const wired_srvloop_wt_window* win, usz i, usz out);
static void wt_ranges_extend_prev(wired_srvloop_wt_window* win, usz i, usz out);
static void wt_ranges_coalesce(wired_srvloop_wt_window* win);
static usz  wt_range_farthest(const wired_srvloop_wt_window* win);
static void wt_range_evict_farthest(wired_srvloop_wt_window* win);
static void wt_range_append(wired_srvloop_wt_window* win, u64 lo, u64 hi);

/* Collapse adjacent/overlapping sorted ranges into one another (a merge that
 * srvloop_wt_range_find_mergeable's single-pass insert can miss when two
 * PRE-existing ranges become touching only after a third insert bridges the gap
 * between them). */
/* 1 if sorted range i touches (or overlaps) the last emitted range at
 * out-1 -- the coalesce condition wt_ranges_coalesce tests each step. */
static int wt_ranges_touches_prev(
    const wired_srvloop_wt_window* win, usz i, usz out) {
  return out > 0 && win->range_lo[i] <= win->range_hi[out - 1];
}

/* Extend the last emitted range (at out-1) to also cover range i, if range i
 * reaches further. */
static void wt_ranges_extend_prev(
    wired_srvloop_wt_window* win, usz i, usz out) {
  if (win->range_hi[i] > win->range_hi[out - 1])
    win->range_hi[out - 1] = win->range_hi[i];
}

static void wt_ranges_coalesce(wired_srvloop_wt_window* win) {
  usz out = 0;
  for (usz i = 0; i < win->range_n; i++) {
    if (wt_ranges_touches_prev(win, i, out)) {
      wt_ranges_extend_prev(win, i, out);
      continue;
    }
    win->range_lo[out] = win->range_lo[i];
    win->range_hi[out] = win->range_hi[i];
    out++;
  }
  win->range_n = out;
}

/* win->frontier = the contiguous byte count starting at 0, i.e. range[0].hi
 * once ranges are sorted/coalesced and range[0].lo == 0; 0 if no range starts
 * at 0. */
void srvloop_wt_window_recompute_frontier(wired_srvloop_wt_window* win) {
  srvloop_wt_ranges_sort(win);
  wt_ranges_coalesce(win);
  win->frontier =
      win->range_n > 0 && win->range_lo[0] == 0 ? win->range_hi[0] : 0;
}

/* The index of the range furthest from the frontier (highest range_lo) --
 * wt_range_evict_farthest's pick of what to sacrifice when the fixed array
 * is full: that range is the one least likely to be the next gap the
 * frontier needs, since every closer range sorts and coalesces first. */
static usz wt_range_farthest(const wired_srvloop_wt_window* win) {
  usz far = 0;
  for (usz i = 1; i < win->range_n; i++)
    if (win->range_lo[i] > win->range_lo[far]) far = i;
  return far;
}

/* Drop the farthest-from-frontier range, sliding the rest down by one, to
 * free a slot for a new incoming range. */
static void wt_range_evict_farthest(wired_srvloop_wt_window* win) {
  usz drop            = wt_range_farthest(win);
  usz last            = win->range_n - 1;
  win->range_lo[drop] = win->range_lo[last];
  win->range_hi[drop] = win->range_hi[last];
  win->range_n--;
}

/* Append [lo, hi) as a brand-new range, evicting the range set's farthest-
 * from-frontier (least useful for advancing it) entry first if the fixed
 * array is already full -- see srvloop_wt_window_insert's own doc for why this
 * is an acceptable fallback rather than a hard cap. Silently dropping the new
 * range instead (the previous behavior) let a stream's frontier wedge
 * forever once 8 disjoint gaps piled up: the dropped bytes never got
 * re-recorded even on retransmission, so delivered_len/MAX_STREAM_DATA
 * stopped advancing for that stream permanently. */
static void wt_range_append(wired_srvloop_wt_window* win, u64 lo, u64 hi) {
  if (win->range_n >= WIRED_SRVLOOP_WT_MAX_RANGES) wt_range_evict_farthest(win);
  win->range_lo[win->range_n] = lo;
  win->range_hi[win->range_n] = hi;
  win->range_n++;
}

void srvloop_wt_window_insert(wired_srvloop_wt_window* win, u64 lo, u64 hi) {
  int m = srvloop_wt_range_find_mergeable(win, lo, hi);
  if (m >= 0)
    srvloop_wt_range_merge_into(win, (usz)m, lo, hi);
  else
    wt_range_append(win, lo, hi);
  srvloop_wt_window_recompute_frontier(win);
}
