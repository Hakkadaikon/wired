#ifndef QUIC_CC_CC_H
#define QUIC_CC_CC_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7: NewReno-style congestion control. Sizes in bytes. */

#define QUIC_MAX_DATAGRAM ((u64)1200)
#define QUIC_CC_MIN_WINDOW (2 * QUIC_MAX_DATAGRAM)   /* kMinimumWindow */
#define QUIC_CC_INIT_WINDOW (10 * QUIC_MAX_DATAGRAM) /* kInitialWindow */

typedef struct {
  u64 cwnd;
  u64 ssthresh;
  int in_recovery;
  u64 recovery_start; /* time the current recovery period began */
} quic_cc;

void quic_cc_init(quic_cc *c);

/* On ACK of `acked` bytes for a packet sent at time `sent_time`. Grows the
 * window unless we are in recovery; an ack of a post-recovery packet exits
 * recovery. */
void quic_cc_on_ack(quic_cc *c, u64 acked, u64 sent_time);

/* On detected loss of a packet sent at `sent_time`: enter recovery and halve
 * the window (never below kMinimumWindow), once per recovery period. */
void quic_cc_on_loss(quic_cc *c, u64 sent_time, u64 now);

/* Persistent congestion: collapse the window to kMinimumWindow. */
void quic_cc_on_persistent(quic_cc *c);

#endif
