#ifndef RECOVERY_PTORESET_H
#define RECOVERY_PTORESET_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 6.2.1: the PTO backoff is reset when an ack-eliciting packet is
 * acknowledged. Returns 1 when the count and timer should be reset. */
int pto_should_reset(int ack_received, u64 ack_eliciting_in_flight);

#endif
