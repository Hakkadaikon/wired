#ifndef PMTU_PMTU_H
#define PMTU_PMTU_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 14.3 / RFC 8899 DPLPMTUD: a sender probes for the largest packet
 * the path carries, starting from the 1200-byte base and raising the
 * validated PMTU as larger probes are acknowledged. A lost probe bounds the
 * search from above; the validated PMTU never drops below the base. */

#define PMTU_BASE 1200
#define PMTU_MAX 1452 /* a common Ethernet-minus-overhead ceiling */
#define PMTU_STEP 64

/* RFC 8899 5.1.2: the default limit on consecutive unsuccessful probes of any
 * one size before concluding it is unsupported. */
#define PMTU_MAX_PROBES 3

/* RFC 8899 5.1.1: PROBE_TIMER MUST NOT be smaller than 1s and SHOULD be
 * larger than 15s. `now`/timestamps here are in microseconds, matching the
 * unit RFC 9002 RTT state (RTT_INITIAL_US) already uses. */
#define PMTU_PROBE_TIMER_US 20000000 /* 20s */

/* RFC 8899 5.2/5.1.1: PMTU_RAISE_TIMER -- while in Search Complete, wait this
 * long before reentering the Search phase (RFC 4821's recommended 600s). */
#define PMTU_RAISE_TIMER_US 600000000 /* 600s */

/* Per-datagram overhead this PL subtracts from the PLPMTU to get the MPS the
 * application may fill with QUIC frame bytes (RFC 8899 4.4): the QUIC short
 * header's worst-case fixed fields (flags + up to 20-byte CID + 4-byte packet
 * number) plus the 16-byte AEAD authentication tag (RFC 9001 5.3). */
#define PMTU_OVERHEAD 41

/** RFC 8899 DPLPMTUD search state: the validated/probe/ceiling/lost sizes,
 * whether a search is in progress, and the probe-loss and timer bookkeeping
 * that drives it. */
typedef struct {
  usz validated;     /* largest packet size confirmed to traverse the path */
  usz probe;         /* size of the probe currently outstanding (0 if none) */
  usz ceiling;       /* upper bound learned from a lost probe */
  usz lost;          /* a size that failed; never probed again (0 if none) */
  int searching;     /* whether a larger size is still worth probing */
  int probe_count;   /* RFC 8899 5.1.3 PROBE_COUNT: consecutive probe losses */
  u64 probe_sent_at; /* RFC 8899 5.1.1 PROBE_TIMER: when `probe` was sent */
  u64 complete_at;   /* RFC 8899 5.1.1 PMTU_RAISE_TIMER: when searching
                      * became 0 (0 while still searching) */
} pmtu;

void pmtu_init(pmtu* p);

/* The size to probe next, or 0 if the search is done. Sets p->probe and, on
 * success, `now` into probe_sent_at (RFC 8899 5.1.1: "each time a probe
 * packet is sent, the PROBE_TIMER is started"). Records `now` into
 * complete_at the moment the search ends (RFC 8899 5.2 Search Complete). */
usz pmtu_next_probe(pmtu* p, u64 now);

/* A probe of `size` was acknowledged: raise the validated PMTU and reset
 * PROBE_COUNT (RFC 8899 5.1.3). */
void pmtu_on_ack(pmtu* p, usz size);

/* A probe of `size` was lost: increments PROBE_COUNT (RFC 8899 5.1.3). Below
 * PMTU_MAX_PROBES this only bounds the search (`ceiling`/`lost`); once
 * PROBE_COUNT exceeds PMTU_MAX_PROBES the size is unsupported, and if
 * `size` was the already-validated PLPMTU this is a black hole (RFC 8899
 * 4.3): validated drops back to PMTU_BASE. */
void pmtu_on_loss(pmtu* p, usz size);

/* RFC 8899 4.4: the Maximum Packet Size the application may fill, derived
 * from the current PLPMTU minus this PL's per-datagram overhead. */
usz pmtu_mps(const pmtu* p);

/* RFC 8899 5.1.1: true once PMTU_PROBE_TIMER_US has elapsed since the
 * outstanding probe was sent without being acked or lost yet -- the probe
 * should be treated as failed (PROBE_COUNT incremented, retried or the
 * search concluded) rather than waited on forever. False when no probe is
 * outstanding. */
int pmtu_probe_timer_due(const pmtu* p, u64 now);

/* RFC 8899 5.2/5.1.1: true once PMTU_RAISE_TIMER_US has elapsed since
 * the search reached Search Complete -- the search should resume. False
 * while still searching (complete_at unset). */
int pmtu_raise_timer_due(const pmtu* p, u64 now);

/* RFC 8899 5.2: reenter the Search phase after the PMTU_RAISE_TIMER fires --
 * clears the ceiling/lost bounds learned by the prior search round so larger
 * candidates already ruled out get a fresh chance, and resets PROBE_COUNT. */
void pmtu_resume_search(pmtu* p);

#endif
