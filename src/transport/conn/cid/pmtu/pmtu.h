#ifndef QUIC_PMTU_PMTU_H
#define QUIC_PMTU_PMTU_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 14.3 / RFC 8899 DPLPMTUD: a sender probes for the largest packet
 * the path carries, starting from the 1200-byte base and raising the
 * validated PMTU as larger probes are acknowledged. A lost probe bounds the
 * search from above; the validated PMTU never drops below the base. */

#define QUIC_PMTU_BASE 1200
#define QUIC_PMTU_MAX 1452 /* a common Ethernet-minus-overhead ceiling */
#define QUIC_PMTU_STEP 64

/* RFC 8899 5.1.2: the default limit on consecutive unsuccessful probes of any
 * one size before concluding it is unsupported. */
#define QUIC_PMTU_MAX_PROBES 3

/* Per-datagram overhead this PL subtracts from the PLPMTU to get the MPS the
 * application may fill with QUIC frame bytes (RFC 8899 4.4): the QUIC short
 * header's worst-case fixed fields (flags + up to 20-byte CID + 4-byte packet
 * number) plus the 16-byte AEAD authentication tag (RFC 9001 5.3). */
#define QUIC_PMTU_OVERHEAD 41

typedef struct {
  usz validated;   /* largest packet size confirmed to traverse the path */
  usz probe;       /* size of the probe currently outstanding (0 if none) */
  usz ceiling;     /* upper bound learned from a lost probe */
  usz lost;        /* a size that failed; never probed again (0 if none) */
  int searching;   /* whether a larger size is still worth probing */
  int probe_count; /* RFC 8899 5.1.3 PROBE_COUNT: consecutive probe losses */
} quic_pmtu;

void quic_pmtu_init(quic_pmtu* p);

/* The size to probe next, or 0 if the search is done. Sets p->probe. */
usz quic_pmtu_next_probe(quic_pmtu* p);

/* A probe of `size` was acknowledged: raise the validated PMTU and reset
 * PROBE_COUNT (RFC 8899 5.1.3). */
void quic_pmtu_on_ack(quic_pmtu* p, usz size);

/* A probe of `size` was lost: increments PROBE_COUNT (RFC 8899 5.1.3). Below
 * QUIC_PMTU_MAX_PROBES this only bounds the search (`ceiling`/`lost`); once
 * PROBE_COUNT exceeds QUIC_PMTU_MAX_PROBES the size is unsupported, and if
 * `size` was the already-validated PLPMTU this is a black hole (RFC 8899
 * 4.3): validated drops back to QUIC_PMTU_BASE. */
void quic_pmtu_on_loss(quic_pmtu* p, usz size);

/* RFC 8899 4.4: the Maximum Packet Size the application may fill, derived
 * from the current PLPMTU minus this PL's per-datagram overhead. */
usz quic_pmtu_mps(const quic_pmtu* p);

#endif
