#ifndef QUIC_CLOSELIFE_IDLETIMEOUT_H
#define QUIC_CLOSELIFE_IDLETIMEOUT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.1: the effective idle timeout is the minimum of the two
 * endpoints' max_idle_timeout values, where 0 means "no advertised limit". */

/* min of the non-zero values; the other if one is 0; 0 if both are 0. */
u64 quic_idle_effective(u64 local, u64 peer);

/* 1 iff a non-zero effective timeout has elapsed since last activity. */
int quic_idle_expired(u64 last_activity, u64 now, u64 effective);

#endif
