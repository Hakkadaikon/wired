#ifndef CC_CCLOSS_H
#define CC_CCLOSS_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7.3.2: recovery-period membership; cc_on_persistent (B.8) is
 * declared in cc.h. */

/* True when a packet sent at sent_time falls within the recovery period. */
int cc_in_recovery(u64 sent_time, u64 recovery_start);

#endif
