#ifndef WIRED_SENDQ_SENDQ_H
#define WIRED_SENDQ_SENDQ_H

#include "common/platform/sys/syscall.h"

/** @file
 * Cursor over a caller-owned response byte stream, slicing it into
 * STREAM-frame-sized chunks (RFC 9000 19.8: offset-addressed stream bytes,
 * FIN on the final slice). The queue borrows the bytes — the caller keeps
 * the storage alive until every slice has been sent and acknowledged. */

typedef struct {
  const u8* p;     /**< borrowed response bytes (caller-owned storage) */
  usz       len;   /**< total stream length */
  usz       cur;   /**< next unsent offset */
  usz       chunk; /**< max bytes per slice */
  /** Ring capacity of the backing storage: 0 (the wired_sendq_init default)
   * = plain linear buffer of len bytes at p. Nonzero: p is a cap-byte ring,
   * offsets are logical stream positions whose bytes live at
   * p + offset % cap (wired_sendq_slice_data), and a slice never crosses
   * the wrap. The caller grows len past cap by reusing ring space -- and is
   * responsible for reclaiming space only once no unacknowledged slice
   * still resolves into it. */
  usz cap;
} wired_sendq;

/** One slice: `len` stream bytes at `offset`, fin set on the last slice. */
typedef struct {
  usz offset;
  usz len;
  int fin;
} wired_sendq_slice;

/** Arm the queue over len bytes at p, sliced into chunk-byte pieces.
 * @param q the queue
 * @param p response bytes (borrowed; must outlive the send)
 * @param len byte count at p
 * @param chunk max bytes per slice (> 0) */
void wired_sendq_init(wired_sendq* q, const u8* p, usz len, usz chunk);

/** Turn q into a ring over cap bytes at its p (see wired_sendq.cap's doc).
 * Call once, right after arming, before any slice is taken.
 * @param q the queue
 * @param cap ring capacity in bytes (>= the currently armed len) */
void wired_sendq_set_ring(wired_sendq* q, usz cap);

/** The storage address slice sl's bytes start at -- p + offset on a linear
 * queue, p + offset % cap on a ring (a slice never crosses the wrap, so
 * its bytes are always contiguous from here).
 * @param q the queue sl came from
 * @param sl a slice from wired_sendq_next
 * @return the first byte of sl's payload */
const u8* wired_sendq_slice_data(
    const wired_sendq* q, const wired_sendq_slice* sl);

/** Take the next unsent slice.
 * @param q the queue
 * @param out receives the slice
 * @return 1 with *out filled, 0 when everything has been handed out. */
int wired_sendq_next(wired_sendq* q, wired_sendq_slice* out);

/** @return 1 once every byte has been handed out (an empty stream counts). */
int wired_sendq_all_sent(const wired_sendq* q);

#endif
