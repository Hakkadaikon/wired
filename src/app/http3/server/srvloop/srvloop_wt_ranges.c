#include "app/http3/server/srvloop/srvloop_impl.h"

static int  wt_range_overlaps(u64 a_lo, u64 a_hi, u64 b_lo, u64 b_hi);
static int  wt_ranges_out_of_order(const wired_srvloop_wt_window* win, usz j);
static void wt_ranges_swap(wired_srvloop_wt_window* win, usz j);
static void wt_ranges_bubble_one(wired_srvloop_wt_window* win, usz i);

void wired_srvloop_wt_uni_slot_release(wired_srvloop* l, u64 stream_id) {
  int i = wired_srvloop_wt_uni_slot_find(l, stream_id);
  if (i < 0) {
    return;
  }
  l->wt_uni_streams[i].in_use = 0;
  wired_srvloop_closed_mark(&l->wt_uni_closed, stream_id);
}

/* draft-ietf-webtrans-http3-15 4.3: byte count of [abs_off, abs_off+n) that
 * falls at or past win.base (the stale, already-delivered prefix is
 * excluded) -- 0 if the whole frame is stale. Split out of
 * wired_srvloop_wt_window_accept to keep its own branch count at the gate. */
usz srvloop_wt_window_skip_stale(
    const wired_srvloop_wt_window* win, u64 abs_off, usz n) {
  u64 end = abs_off + n;
  if (end <= win->base) {
    return 0;
  }
  return abs_off >= win->base ? n : (usz)(end - win->base);
}

/* Insert [rel_lo, rel_hi) into win's sorted/merged range set (relative to
 * win->base), then recompute frontier -- linear insertion-sort-with-merge
 * over a small fixed array (WIRED_SRVLOOP_WT_MAX_RANGES), the whole set
 * rebuilt each call rather than incrementally spliced, so the branch count
 * per helper stays at the CCN gate. A range beyond the array's capacity is
 * silently coalesced into the nearest overlapping one where possible, or
 * dropped if none overlaps (ponytail: a real workload never opens more than
 * WIRED_SRVLOOP_WT_MAX_RANGES disjoint gaps on one stream inside one window,
 * so this is not reachable at the sizes this SDK targets). */
static int wt_range_overlaps(u64 a_lo, u64 a_hi, u64 b_lo, u64 b_hi) {
  return a_lo <= b_hi && b_lo <= a_hi;
}

/* Merge [lo, hi) into ranges[i], growing it, then return 1 (used by the
 * insert loop below to fold a new/expanding range into an existing entry). */
void srvloop_wt_range_merge_into(
    wired_srvloop_wt_window* win, usz i, u64 lo, u64 hi) {
  if (lo < win->range_lo[i]) {
    win->range_lo[i] = lo;
  }
  if (hi > win->range_hi[i]) {
    win->range_hi[i] = hi;
  }
}

/* The index of an existing range overlapping/adjacent to [lo, hi), or -1. */
int srvloop_wt_range_find_mergeable(
    const wired_srvloop_wt_window* win, u64 lo, u64 hi) {
  for (usz i = 0; i < win->range_n; i++) {
    if (wt_range_overlaps(win->range_lo[i], win->range_hi[i], lo, hi)) {
      return (int)i;
    }
  }
  return -1;
}

/* Sort win's ranges by range_lo (small fixed array, insertion sort) so
 * srvloop_wt_window_recompute_frontier can walk them in order. */
/* 1 if ranges j-1 and j are out of order (j-1's lo is higher) -- the swap
 * condition srvloop_wt_ranges_sort's insertion sort tests each step. */
static int wt_ranges_out_of_order(const wired_srvloop_wt_window* win, usz j) {
  return j > 0 && win->range_lo[j - 1] > win->range_lo[j];
}

/* Swap ranges j-1 and j in place. */
static void wt_ranges_swap(wired_srvloop_wt_window* win, usz j) {
  u64 lo               = win->range_lo[j - 1];
  u64 hi               = win->range_hi[j - 1];
  win->range_lo[j - 1] = win->range_lo[j];
  win->range_hi[j - 1] = win->range_hi[j];
  win->range_lo[j]     = lo;
  win->range_hi[j]     = hi;
}

/* Insertion-sort ranges[0..range_n) into ascending range_lo order (a small
 * fixed array, so O(n^2) insertion sort is simplest and fast enough). */
static void wt_ranges_bubble_one(wired_srvloop_wt_window* win, usz i) {
  usz j = i;
  while (wt_ranges_out_of_order(win, j)) {
    wt_ranges_swap(win, j);
    j--;
  }
}

void srvloop_wt_ranges_sort(wired_srvloop_wt_window* win) {
  for (usz i = 1; i < win->range_n; i++) {
    wt_ranges_bubble_one(win, i);
  }
}
