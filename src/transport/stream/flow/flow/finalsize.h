#ifndef QUIC_FLOW_FINALSIZE_H
#define QUIC_FLOW_FINALSIZE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.5: a stream's final size is the byte offset just past its last
 * byte, learned from a FIN-bearing STREAM frame or a RESET_STREAM. Once
 * known it is immutable, no data may arrive at or beyond it, and it may not
 * contradict the highest offset already seen. Any violation is a
 * FINAL_SIZE_ERROR. */

typedef struct {
  u64 highest;    /* highest offset+len seen so far */
  u64 final_size; /* valid once known */
  int known;
} quic_finalsize;

void quic_finalsize_init(quic_finalsize* f);

/* Record that data occupies [offset, offset+len). Returns 1 if consistent,
 * 0 (FINAL_SIZE_ERROR) if it reaches at or beyond a known final size. */
int quic_finalsize_data(quic_finalsize* f, u64 offset, u64 len);

/* Record the final size. Returns 1 if consistent, 0 (FINAL_SIZE_ERROR) if it
 * differs from a previously known value or is below the highest offset seen. */
int quic_finalsize_set(quic_finalsize* f, u64 size);

/* RFC 9000 4.4: a bidirectional stream's two directions are independent --
 * RESET_STREAM (send direction) or a peer's RESET_STREAM (recv direction)
 * fixes only that direction's final size and never disturbs the other,
 * which keeps tracking its own flow control state until it separately
 * reaches a terminal state. */
typedef struct {
  quic_finalsize send;
  quic_finalsize recv;
} quic_dual_finalsize;

void quic_dual_finalsize_init(quic_dual_finalsize* d);

/* Fix the send direction's final size (e.g. on sending/receiving the
 * RESET_STREAM that terminates it). Returns 1 if consistent, 0
 * (FINAL_SIZE_ERROR) on conflict; the recv direction is untouched either
 * way. */
int quic_dual_finalsize_reset_send(quic_dual_finalsize* d, u64 size);

/* Same as quic_dual_finalsize_reset_send, but for the recv direction; the
 * send direction is untouched either way. */
int quic_dual_finalsize_reset_recv(quic_dual_finalsize* d, u64 size);

#endif
