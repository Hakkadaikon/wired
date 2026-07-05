#ifndef QUIC_CC_HYSTART_H
#define QUIC_CC_HYSTART_H

#include "common/platform/sys/syscall.h"

/* RFC 9406 HyStart++: leave slow start early when the round-trip time rises
 * across rounds — before the first loss would end it. Pure detection state;
 * the caller feeds one RTT sample per ACK and acts on the verdict (set
 * ssthresh = cwnd).
 * ponytail: the CSS probation phase is folded into a direct exit (more
 * conservative — a spurious exit only costs earlier congestion avoidance);
 * add CSS when real traces show premature exits. */

typedef struct {
  u64 last_round_min; /* previous round's min RTT (~0 before round 2) */
  u64 curr_round_min; /* running min of the current round (~0 when empty) */
  usz samples;        /* RTT samples seen this round */
  u64 round_end_pn;   /* first pn of the next round (round boundary) */
  int have_boundary;  /* 1 once round_end_pn is armed */
} quic_hystart;

void quic_hystart_init(quic_hystart* h);

/* Feed one RTT sample for an ACK of acked_pn; next_pn (the next packet
 * number the sender would use) becomes the boundary that ends the current
 * round. Returns 1 when slow start should end now (RFC 9406 4.2: at least 8
 * samples in the round and the round min exceeds last round's min by
 * clamp(4ms, last/8, 16ms)). */
int quic_hystart_sample(quic_hystart* h, u64 rtt_ms, u64 acked_pn, u64 next_pn);

#endif
