#ifndef QUIC_CC_CC_H
#define QUIC_CC_CC_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/congestion/cc/bbr.h"

/* RFC 9002 7: NewReno-style congestion control. Sizes in bytes. */

#define QUIC_MAX_DATAGRAM ((u64)1200)
#define QUIC_CC_MIN_WINDOW (2 * QUIC_MAX_DATAGRAM)   /* kMinimumWindow */
#define QUIC_CC_INIT_WINDOW (10 * QUIC_MAX_DATAGRAM) /* kInitialWindow */

/* Window-growth algorithm (RFC 9002 7 NewReno, RFC 9438 CUBIC). */
#define QUIC_CC_ALGO_NEWRENO 0
#define QUIC_CC_ALGO_CUBIC 1
#define QUIC_CC_ALGO_BBR 2

typedef struct {
  u64      cwnd;
  u64      ssthresh;
  int      in_recovery;
  u64      recovery_start; /* time the current recovery period began */
  int      algo;           /* QUIC_CC_ALGO_* */
  u64      w_max_seg;      /* CUBIC: window at the last loss, in segments */
  u64      k_ms;           /* CUBIC: plateau offset for the current epoch */
  u64      epoch_ms;       /* CUBIC: when the current epoch (loss) began */
  quic_bbr bbr;            /* BBR: phase machine and estimators */
  u64      round_bytes;    /* BBR: bytes acked in the current sample round */
  u64      round_start_ms; /* BBR: when the current sample round began */
} quic_cc;

void quic_cc_init(quic_cc* c); /* NewReno */

/* Init with an explicit algorithm (QUIC_CC_ALGO_*). */
void quic_cc_init_algo(quic_cc* c, int algo);

/* On ACK of `acked` bytes for a packet sent at time `sent_time`, observed at
 * `now`. Grows the window unless we are in recovery; an ack of a
 * post-recovery packet exits recovery. CUBIC lifts cwnd onto the cubic curve
 * evaluated at `now` once a loss has anchored an epoch. */
void quic_cc_on_ack(quic_cc* c, u64 acked, u64 sent_time, u64 now);

/* On detected loss of a packet sent at `sent_time`: enter recovery and halve
 * the window (never below kMinimumWindow), once per recovery period. */
void quic_cc_on_loss(quic_cc* c, u64 sent_time, u64 now);

/* Persistent congestion: collapse the window to kMinimumWindow. */
void quic_cc_on_persistent(quic_cc* c);

/* BBR housekeeping, once per step after acks: closes a sample round when at
 * least one rtprop has elapsed (feeding the delivery rate to the phase
 * machine), runs the drain handoff against the caller's in-flight bytes,
 * the PROBE_RTT entry/exit checks, and recomputes cwnd = cwnd_gain x BDP.
 * No-op for the other algorithms. */
void quic_cc_bbr_tick(quic_cc* c, u64 inflight_bytes, u64 now_ms);

/* Milliseconds to wait between paced sends: pacing_gain x BtlBw for BBR
 * (floored at 1ms once bandwidth is known), the srtt-derived interval
 * otherwise. */
u64 quic_cc_pacing_ms(const quic_cc* c, u64 srtt_ms, u64 mtu);

#endif
