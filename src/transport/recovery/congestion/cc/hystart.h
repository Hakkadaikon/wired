#ifndef CC_HYSTART_H
#define CC_HYSTART_H

#include "common/platform/sys/syscall.h"

/* RFC 9406 HyStart++: leave slow start early when the round-trip time rises
 * across rounds — before the first loss would end it. Pure detection state;
 * the caller feeds one RTT sample per ACK, scales slow-start growth with
 * hystart_acked, and acts on the verdict (set ssthresh = cwnd). A rise
 * first enters Conservative Slow Start (RFC 9406 4.2); the verdict comes
 * after CSS_ROUNDS rounds there. */

/** Per-round RTT tracking state for the HyStart++ rise detector. */
typedef struct {
  u64 last_round_min; /* previous round's min RTT (~0 before round 2) */
  u64 curr_round_min; /* running min of the current round (~0 when empty) */
  usz samples;        /* RTT samples seen this round */
  u64 round_end_pn;   /* first pn of the next round (round boundary) */
  int have_boundary;  /* 1 once round_end_pn is armed */
  int css;            /* 1 while in Conservative Slow Start */
  u64 css_baseline;   /* round min RTT when CSS was entered */
  usz css_rounds;     /* round ends seen while in CSS */
} hystart;

void hystart_init(hystart* h);

/* Feed one RTT sample for an ACK of acked_pn; next_pn (the next packet
 * number the sender would use) becomes the boundary that ends the current
 * round. RFC 9406 4.2: at least 8 samples in the round and the round min
 * exceeding last round's min by clamp(4ms, last/8, 16ms) enters CSS; in CSS
 * a round min back below the CSS baseline resumes slow start. Returns 1
 * when slow start should end now: CSS_ROUNDS (5) rounds spent in CSS. */
int hystart_sample(hystart* h, u64 rtt_ms, u64 acked_pn, u64 next_pn);

/* The bytes slow start should grow cwnd by for acked newly-acked bytes:
 * acked / CSS_GROWTH_DIVISOR (4) in CSS, acked otherwise. */
u64 hystart_acked(const hystart* h, u64 acked);

#endif
