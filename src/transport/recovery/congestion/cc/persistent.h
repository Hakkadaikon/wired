#ifndef CC_PERSISTENT_H
#define CC_PERSISTENT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7.6: persistent congestion. Sizes in bytes, durations in the
 * caller's time unit. */

/* True when the loss period exceeds kPersistentCongestionThreshold (3) PTOs
 * (RFC 9002 7.6.2: "exceeds", so exactly 3 PTOs does not qualify). */
int cc_persistent(u64 loss_period, u64 pto);

/* Window after persistent congestion: kMinimumWindow = 2 * max_datagram. */
u64 cc_persistent_cwnd(u64 max_datagram);

#endif
