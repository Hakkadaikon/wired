#ifndef CC_PERSISTENT_H
#define CC_PERSISTENT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7.6: persistent congestion. Durations in the caller's time unit. */

/* True when the loss period exceeds kPersistentCongestionThreshold (3) PTOs
 * (RFC 9002 7.6.2: "exceeds", so exactly 3 PTOs does not qualify). */
int cc_persistent(u64 loss_period, u64 pto);

#endif
