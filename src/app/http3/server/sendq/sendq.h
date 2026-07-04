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

/** Take the next unsent slice.
 * @param q the queue
 * @param out receives the slice
 * @return 1 with *out filled, 0 when everything has been handed out. */
int wired_sendq_next(wired_sendq* q, wired_sendq_slice* out);

/** @return 1 once every byte has been handed out (an empty stream counts). */
int wired_sendq_all_sent(const wired_sendq* q);

#endif
