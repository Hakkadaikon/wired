#ifndef PMTU_PMTU_H
#define PMTU_PMTU_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 14.3 / RFC 8899 DPLPMTUD: a sender probes for the largest packet
 * the path carries, starting from the 1200-byte base and raising the
 * validated PMTU as larger probes are acknowledged. A size lost MAX_PROBES
 * times bounds the search from above; the validated PMTU never drops below
 * the base. */

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

/* RFC 8899 5.2 state machine phases. DISABLED (0) is what a zeroed pmtu
 * reads as: it never probes. The connection handshake confirms BASE_PLPMTU
 * implicitly (1200-byte-padded Initials), so pmtu_init starts in SEARCHING;
 * BASE is re-entered only after a black hole, and ERROR after BASE_PLPMTU
 * itself failed MAX_PROBES times (RFC 9000 14: the path is then unusable
 * except for probes and CONNECTION_CLOSE, see pmtu_halted). */
#define PMTU_PHASE_DISABLED 0
#define PMTU_PHASE_BASE 1
#define PMTU_PHASE_SEARCHING 2
#define PMTU_PHASE_COMPLETE 3
#define PMTU_PHASE_ERROR 4

/** RFC 8899 DPLPMTUD search state: the validated/probe/ceiling/lost sizes,
 * the state machine phase, and the probe-loss, data-loss and timer
 * bookkeeping that drives it. */
typedef struct {
  usz validated;     /* largest packet size confirmed to traverse the path */
  usz probe;         /* size of the probe currently outstanding (0 if none) */
  usz ceiling;       /* upper bound learned from MAX_PROBES lost probes */
  usz lost;          /* a size concluded unsupported; not probed again */
  usz max;           /* RFC 8899 5.1.2 MAX_PLPMTU of this path (pmtu_set_max) */
  int phase;         /* PMTU_PHASE_* */
  int probe_count;   /* RFC 8899 5.1.3 PROBE_COUNT: consecutive probe losses */
  int big_lost;      /* RFC 8899 4.3: above-base data packets lost since the
                      * newest acked one (pmtu_on_big_losses) */
  u64 big_acked_pn;  /* newest packet number of an acked above-base packet */
  u64 probe_sent_at; /* RFC 8899 5.1.1 PROBE_TIMER: when `probe` was sent */
  u64 complete_at;   /* RFC 8899 5.1.1 PMTU_RAISE_TIMER: when the search
                      * reached SEARCH_COMPLETE */
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

/* A probe of `size` was lost: increments PROBE_COUNT (RFC 8899 5.1.3).
 * Below PMTU_MAX_PROBES the same size is simply probed again (RFC 8899 5.2:
 * a loss for any reason must not by itself end the search, 5.3.3/8). Once
 * PROBE_COUNT reaches PMTU_MAX_PROBES the verdict depends on the phase:
 * SEARCHING caps the search at `size`; a lost probe at the validated PLPMTU
 * is a black hole (RFC 8899 4.3, back to BASE); BASE moves to ERROR. */
void pmtu_on_loss(pmtu* p, usz size);

/* RFC 8899 3.5/5.1.2: bound MAX_PLPMTU (and so the search ceiling) by what
 * the local link can carry, clamped to [PMTU_BASE, PMTU_MAX]. */
void pmtu_set_max(pmtu* p, usz max);

/* RFC 8899 4.3 data-loss black hole detection: `pn`, a data packet larger
 * than a BASE_PLPMTU packet could carry, was acknowledged -- the path still
 * delivers such packets, so earlier losses of them are not a black hole. */
void pmtu_on_big_ack(pmtu* p, u64 pn);

/* 1 if a lost above-base data packet `pn` counts toward a black hole: it was
 * sent after the newest acknowledged one. */
int pmtu_big_suspect(const pmtu* p, u64 pn);

/* `n` above-base data packets (each pmtu_big_suspect) were declared lost.
 * PMTU_MAX_PROBES of them with no newer one acknowledged means the path no
 * longer carries the PLPMTU (RFC 8899 4.3): back to BASE. Only while
 * SEARCHING/SEARCH_COMPLETE above the base. */
void pmtu_on_big_losses(pmtu* p, usz n);

/* RFC 9000 14 / RFC 8899 5.2 ERROR: the path is not known to carry
 * BASE_PLPMTU; nothing but PMTU probes and CONNECTION_CLOSE may be sent. */
int pmtu_halted(const pmtu* p);

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
 * resets the ceiling to MAX_PLPMTU and clears the lost bound learned by the
 * prior search round so larger candidates already ruled out get a fresh
 * chance, and resets PROBE_COUNT. */
void pmtu_resume_search(pmtu* p);

#endif
