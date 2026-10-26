#ifndef TLS_TICKETVERSION_H
#define TLS_TICKETVERSION_H

#include "common/platform/sys/syscall.h"

/* RFC 9369 5: "Servers MUST validate the originating version of any session
 * ticket or token and not accept one issued from a different version." A
 * ticket records the version of the connection it was issued on (the
 * negotiated one after compatible version negotiation); a rejected one falls
 * back to a full handshake without 0-RTT. */

/* Returns 1 when a ticket from `ticket_version` may be used to resume on
 * `current_version`: only the very same version. */
int ticket_version_ok(u32 ticket_version, u32 current_version);

#endif
