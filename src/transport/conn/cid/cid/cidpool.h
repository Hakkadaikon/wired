#ifndef QUIC_CID_CIDPOOL_H
#define QUIC_CID_CIDPOOL_H

#include "common/platform/sys/syscall.h"

/* Connection ID issuance/retirement bookkeeping (RFC 9000 5.1.1, 5.1.2).
 *
 * We track only sequence numbers, not the CID bytes: issued sequence numbers
 * form a contiguous range [retire_lo, next_seq). Everything below retire_lo
 * has been retired by a retire_prior_to. The active count is the size of that
 * range and must never exceed the peer's active_connection_id_limit. */
typedef struct {
    u64 limit;     /* peer's active_connection_id_limit (RFC 9000 18.2) */
    u64 next_seq;  /* next sequence number to issue */
    u64 retire_lo; /* lowest still-active sequence number */
} quic_cidpool;

/* Initialise a pool with the peer's active_connection_id_limit. The limit is
 * at least 2 per RFC 9000 5.1.1, but we accept whatever the peer sent. */
void quic_cidpool_init(quic_cidpool *p, u64 limit);

/* Number of issued-but-not-retired connection IDs. */
u64 quic_cidpool_active_count(const quic_cidpool *p);

/* Issue the next sequence number. On success writes it to *seq and returns 1.
 * Returns 0 if issuing would exceed the active limit (the caller would have
 * to retire one first; sending more is a CONNECTION_ID_LIMIT_ERROR). */
int quic_cidpool_issue(quic_cidpool *p, u64 *seq);

/* Retire every sequence number below retire_prior_to (RFC 9000 5.1.2).
 * Returns 1 on success. Returns 0 if retire_prior_to exceeds next_seq, which
 * would retire a sequence number that was never issued (PROTOCOL_VIOLATION).
 * A retire_prior_to at or below the current floor is a no-op success. */
int quic_cidpool_retire_prior_to(quic_cidpool *p, u64 retire_prior_to);

#endif
