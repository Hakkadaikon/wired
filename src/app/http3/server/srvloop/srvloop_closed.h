#ifndef SRVLOOP_CLOSED_H
#define SRVLOOP_CLOSED_H

#include "common/platform/sys/syscall.h"

/* The closed-stream set of wired_srvloop (srvloop_wt.h), split out for the
 * Halstead file cap. */

/** RFC 9000 3.2: closed client stream indexes (id / 4) of one stream type
 * -- every index below floor, plus the 1024 just above it in bm (bit k =
 * index floor + k). A late duplicate of a closed stream is discarded, not
 * re-admitted. Ceiling: a mark past the window slides it up 64 indexes at
 * a time, so indexes left behind count as closed even if a long-lived
 * stream among them is still open -- harmless, since a live stream's slot
 * is always found before this set is consulted. */
typedef struct {
  u64 floor;  /**< every index below this is closed */
  u64 bm[16]; /**< the 1024 indexes from floor up */
} wired_srvloop_closed;

/** Record stream_id's id-space index in w (see srvloop.c's closed-set doc:
 * exact ids over a sliding 1024-index window; an id past the window slides
 * it up, counting every index left behind as recorded). */
void wired_srvloop_closed_mark(wired_srvloop_closed* w, u64 stream_id);

/** 1 if stream_id's index is recorded in w (or below its window). */
int wired_srvloop_closed_has(const wired_srvloop_closed* w, u64 stream_id);

#endif
