#ifndef QUIC_H3_GOAWAY_CHECK_H
#define QUIC_H3_GOAWAY_CHECK_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 5.2. A GOAWAY sent by a server carries a client-initiated
 * bidirectional Stream ID (the low two bits are 00, i.e. id % 4 == 0); one sent
 * by a client carries a Push ID, which has no such constraint. A peer that
 * receives a GOAWAY whose identifier has the wrong type MUST treat it as an
 * H3_ID_ERROR. */

/* Returns 1 if id is a valid GOAWAY identifier from this sender, else 0.
 * from_server selects the server rule (client bidi Stream ID) over the client
 * rule (any Push ID). */
int h3_goaway_id_ok(u64 id, int from_server);

#endif
