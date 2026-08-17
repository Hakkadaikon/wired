#ifndef CC_PERSISTENT_H
#define CC_PERSISTENT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7.6: persistent congestion. Sizes in bytes, durations in the
 * caller's time unit. */

/* True when the loss period spans at least kPersistentCongestionThreshold (3)
 * PTOs. */
int cc_persistent(u64 loss_period, u64 pto);

/* Window after persistent congestion: kMinimumWindow = 2 * max_datagram. */
u64 cc_persistent_cwnd(u64 max_datagram);

#endif
