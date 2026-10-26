#ifndef FLOW_FINALSIZE_H
#define FLOW_FINALSIZE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.5: a stream's final size is the byte offset just past its last
 * byte, learned from a FIN-bearing STREAM frame or a RESET_STREAM. Once
 * known it is immutable, no data may arrive at or beyond it, and it may not
 * contradict the highest offset already seen. Any violation is a
 * FINAL_SIZE_ERROR. */

/** One stream direction's final-size state (RFC 9000 4.5). */
typedef struct {
  u64 highest;    /**< highest offset+len seen so far */
  u64 final_size; /**< valid once known */
  int known;      /**< 1 once a FIN or RESET_STREAM fixed final_size */
} finalsize;

void finalsize_init(finalsize* f);

/* Record that data occupies [offset, offset+len). Returns 1 if consistent,
 * 0 (FINAL_SIZE_ERROR) if it reaches at or beyond a known final size. */
int finalsize_data(finalsize* f, u64 offset, u64 len);

/* Record the final size. Returns 1 if consistent, 0 (FINAL_SIZE_ERROR) if it
 * differs from a previously known value or is below the highest offset seen. */
int finalsize_set(finalsize* f, u64 size);

#endif
