#ifndef QUIC_CLOSELIFE_DRAINING_H
#define QUIC_CLOSELIFE_DRAINING_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.2.2: after an immediate close the endpoint enters the draining
 * period of 3*PTO, during which it sends no new packets and only receives. */

/* The draining period in the same time unit as `pto`. */
u64 quic_draining_period(u64 pto);

/* True once now has reached close_time + 3*PTO (draining is over). */
int quic_draining_done(u64 close_time, u64 now, u64 pto);

/* Whether sending is permitted: forbidden while in_draining is set. */
int quic_draining_may_send(int in_draining);

#endif
