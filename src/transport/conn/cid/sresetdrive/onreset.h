#ifndef QUIC_SRESETDRIVE_ONRESET_H
#define QUIC_SRESETDRIVE_ONRESET_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.3 acting on a detected stateless reset. On detection the
 * connection enters the draining state immediately and is closed silently:
 * no further packets are sent and no close frame is emitted. */

/* 1 if a detected reset (is_reset != 0) means the connection must close. */
int quic_sresetdrive_on_detected(int is_reset);

#endif
