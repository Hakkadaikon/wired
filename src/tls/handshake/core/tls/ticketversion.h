#ifndef TLS_TICKETVERSION_H
#define TLS_TICKETVERSION_H

#include "common/platform/sys/syscall.h"

/* RFC 9369 5 / RFC 9001: a session ticket records the QUIC version of the
 * connection it was issued on. On resumption the recorded version must match
 * or be compatible with the version now in use. */

/* Returns 1 when a ticket from `ticket_version` may be used to resume on
 * `current_version`: identical, or compatible versions. */
int ticket_version_ok(u32 ticket_version, u32 current_version);

/* Returns 1 when 0-RTT may be attempted on resumption: only when the ticket
 * and current versions are compatible (RFC 9369 5). */
int ticket_0rtt_ok(u32 ticket_version, u32 current_version);

#endif
