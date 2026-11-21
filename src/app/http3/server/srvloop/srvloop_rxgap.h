#ifndef APP_HTTP3_SERVER_SRVLOOP_SRVLOOP_RXGAP_H
#define APP_HTTP3_SERVER_SRVLOOP_SRVLOOP_RXGAP_H

/* RFC 9000 2.2 / 21.9: the holes below one stream's highest received
 * offset, so a frame below it can be told apart: one filling a hole brings
 * bytes never received before (progress), a duplicate brings none.
 * Included by srvloop_rxacct.h; inline, like the other per-frame helpers. */

#include "common/bytes/util/num.h"
#include "common/platform/sys/syscall.h"

/** Holes tracked per stream (16 bytes each).
 * shortcut: a hole past the 8th is not recorded and its later fill counts
 * as no progress. A stream's window bounds its holes to window / (2 x frame
 * length): at most 4 on a 10240-byte request stream and 20 on a 49152-byte
 * WT or uni stream at 1200-byte frames, so a legitimate peer only trips the
 * limit with about 49 WT streams losing every other frame at once, or with
 * tiny frames. */
#define WIRED_SRVLOOP_RXGAPS 8

/** Missing ranges [lo[i], hi[i]) below the highest offset; lo == hi marks a
 * free entry, so a zeroed value holds none. */
typedef struct {
  u64 lo[WIRED_SRVLOOP_RXGAPS]; /**< first missing offset */
  u64 hi[WIRED_SRVLOOP_RXGAPS]; /**< one past the last missing offset */
} srvloop_rxgap;

/* The first free entry, WIRED_SRVLOOP_RXGAPS if none. */
static inline usz srvloop_rxgap_free(const srvloop_rxgap* g) {
  for (usz i = 0; i < WIRED_SRVLOOP_RXGAPS; i++) {
    if (g->lo[i] == g->hi[i]) {
      return i;
    }
  }
  return WIRED_SRVLOOP_RXGAPS;
}

/* Record the hole [lo, hi) if it is not empty and an entry is free. */
static inline void srvloop_rxgap_add(srvloop_rxgap* g, u64 lo, u64 hi) {
  usz i = srvloop_rxgap_free(g);
  if (lo >= hi || i == WIRED_SRVLOOP_RXGAPS) {
    return;
  }
  g->lo[i] = lo;
  g->hi[i] = hi;
}

/* The bytes of [off, end) inside hole i, cut out of it: its left part stays
 * in entry i, its right part takes a free entry. */
static inline u64 srvloop_rxgap_cut(srvloop_rxgap* g, usz i, u64 off, u64 end) {
  u64 a  = u64_max(g->lo[i], off);
  u64 b  = u64_min(g->hi[i], end);
  u64 hi = g->hi[i];
  if (a >= b) {
    return 0;
  }
  g->hi[i] = a;
  srvloop_rxgap_add(g, b, hi);
  return b - a;
}

/* The bytes of [off, end) never received before on a stream whose highest
 * offset was highest; a jump past it leaves the hole [highest, off). */
static inline u64 srvloop_rxgap_fresh(
    srvloop_rxgap* g, u64 highest, u64 off, u64 end) {
  u64 n   = end - u64_min(u64_max(off, highest), end);
  u64 top = u64_min(end, highest);
  for (usz i = 0; i < WIRED_SRVLOOP_RXGAPS; i++) {
    n += srvloop_rxgap_cut(g, i, off, top);
  }
  srvloop_rxgap_add(g, highest, off);
  return n;
}

#endif
