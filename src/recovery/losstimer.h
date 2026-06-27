#ifndef QUIC_RECOVERY_LOSSTIMER_H
#define QUIC_RECOVERY_LOSSTIMER_H

#include "sys/syscall.h"

/* RFC 9002 6.2 loss detection timer selection. Times in us. */

/* If a loss time is set, the timer fires at the earlier of loss_time and
 * pto_time; otherwise it fires at pto_time. */
u64 quic_losstimer_next(u64 loss_time, u64 pto_time, int has_loss_time);

/* The PTO timer is armed only while ack-eliciting packets are in flight. */
int quic_losstimer_set(int ack_eliciting_in_flight);

#endif
