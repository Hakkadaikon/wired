#ifndef QUIC_PATH_ANTIAMP_H
#define QUIC_PATH_ANTIAMP_H

#include "common/platform/sys/syscall.h"

/* Anti-amplification limit (RFC 9000 8.1): before a path is validated, an
 * endpoint may send at most three times the number of bytes it has received
 * on that path. These helpers compute the remaining budget for an
 * unvalidated path; once validated the limit no longer applies. */

/* Bytes still sendable before hitting the 3x limit: 3*received - sent, or 0
 * if already at or over the limit. */
u64 quic_antiamp_budget(u64 received, u64 sent);

/* Whether sending `want` more bytes stays within the 3x limit. */
int quic_antiamp_can_send(u64 received, u64 sent, u64 want);

#endif
