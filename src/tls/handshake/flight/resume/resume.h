#ifndef QUIC_RESUME_RESUME_H
#define QUIC_RESUME_RESUME_H

#include "common/platform/sys/syscall.h"

/* Resumption driver: hold a TLS session ticket (RFC 8446 4.6.1) across
 * connections and decide whether 0-RTT may be attempted on a later connection
 * (RFC 9001 4.6, RFC 9000 7). A Retry between attempts does not invalidate the
 * ticket (RFC 9000 8.1, 17.2.5): the resumed Initial carries both the Retry
 * token and the resumption PSK. */

#define QUIC_RESUME_TICKET_MAX 512

typedef struct {
    u8  ticket[QUIC_RESUME_TICKET_MAX];
    usz ticket_len;
    u64 issued_at;       /* RFC 8446 4.6.1 ticket issuance time */
    u32 lifetime;        /* ticket_lifetime, seconds */
    u64 max_data;        /* RFC 9000 7.4.1: remembered initial_max_data */
    int have_ticket;
} quic_resume;

/* Store a ticket and the transport parameters to remember for 0-RTT.
 * Returns 1 on success, 0 if the ticket does not fit. RFC 8446 4.6.1. */
int quic_resume_store(quic_resume *r, const u8 *ticket, usz len,
                      u64 issued_at, u32 lifetime, u64 max_data);

/* Returns 1 when a stored ticket is still within its lifetime at `now`
 * (seconds, same clock as issued_at). RFC 8446 4.6.1. */
int quic_resume_valid(const quic_resume *r, u64 now);

/* Returns 1 when the new connection's transport parameters are no more
 * permissive than those remembered, so 0-RTT data stays within limits.
 * RFC 9001 4.6 / RFC 9000 7.4.1. */
int quic_resume_tp_compatible(u64 remembered_max_data, u64 new_max_data);

/* Returns 1 when 0-RTT may be attempted: ticket valid and transport
 * parameters compatible. RFC 9001 4.6. */
int quic_resume_can_0rtt(const quic_resume *r, int ticket_valid,
                         int tp_compatible);

/* Returns 1 when the stored ticket remains usable after a Retry. A Retry never
 * invalidates resumption. RFC 9000 8.1 / 17.2.5. */
int quic_resume_after_retry(const quic_resume *r, int retry_received);

#endif
