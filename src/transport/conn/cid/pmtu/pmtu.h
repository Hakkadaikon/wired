#ifndef QUIC_PMTU_PMTU_H
#define QUIC_PMTU_PMTU_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 14.3 / RFC 8899 DPLPMTUD: a sender probes for the largest packet
 * the path carries, starting from the 1200-byte base and raising the
 * validated PMTU as larger probes are acknowledged. A lost probe bounds the
 * search from above; the validated PMTU never drops below the base. */

#define QUIC_PMTU_BASE 1200
#define QUIC_PMTU_MAX  1452 /* a common Ethernet-minus-overhead ceiling */
#define QUIC_PMTU_STEP 64

typedef struct {
    usz validated;   /* largest packet size confirmed to traverse the path */
    usz probe;       /* size of the probe currently outstanding (0 if none) */
    usz ceiling;     /* upper bound learned from a lost probe */
    int searching;   /* whether a larger size is still worth probing */
} quic_pmtu;

void quic_pmtu_init(quic_pmtu *p);

/* The size to probe next, or 0 if the search is done. Sets p->probe. */
usz quic_pmtu_next_probe(quic_pmtu *p);

/* A probe of `size` was acknowledged: raise the validated PMTU. */
void quic_pmtu_on_ack(quic_pmtu *p, usz size);

/* A probe of `size` was lost: it bounds the search from above. */
void quic_pmtu_on_loss(quic_pmtu *p, usz size);

#endif
