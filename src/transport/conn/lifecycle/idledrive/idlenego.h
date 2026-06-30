#ifndef QUIC_IDLEDRIVE_IDLENEGO_H
#define QUIC_IDLEDRIVE_IDLENEGO_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.1: the effective max_idle_timeout is the minimum of the two
 * endpoints' advertised values, where 0 means "no limit advertised". */

/* min of the non-zero values; the other if one is 0; 0 if both are 0. */
u64 quic_idledrive_effective(u64 local_timeout, u64 peer_timeout);

#endif
