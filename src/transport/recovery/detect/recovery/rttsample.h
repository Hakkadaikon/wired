#ifndef RECOVERY_RTTSAMPLE_H
#define RECOVERY_RTTSAMPLE_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 5.1/5.3: min_rtt tracking and ack_delay adjustment. */

u64 rtt_min_update(u64 min_rtt, u64 latest_rtt);
u64 rtt_adjusted(u64 latest_rtt, u64 min_rtt, u64 ack_delay);

#endif
