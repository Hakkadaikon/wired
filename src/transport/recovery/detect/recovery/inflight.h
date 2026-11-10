#ifndef RECOVERY_INFLIGHT_H
#define RECOVERY_INFLIGHT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 2: in-flight iff ack-eliciting or carrying PADDING (consumes
 * congestion bytes). */
int pkt_in_flight(int ack_eliciting, int has_padding);

#endif
