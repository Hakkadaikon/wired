#ifndef QUIC_CC_CCLOSS_H
#define QUIC_CC_CCLOSS_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7.3.2: window reduction on loss and recovery-period membership.
 * Sizes in bytes. */

/* New ssthresh on loss: cwnd * kLossReductionFactor (0.5). */
u64 cc_on_loss_ssthresh(u64 cwnd);

/* New cwnd on loss: max(ssthresh, kMinimumWindow = 2 * max_datagram). */
u64 cc_on_loss_cwnd(u64 cwnd, u64 max_datagram);

/* True when a packet sent at sent_time falls within the recovery period. */
int cc_in_recovery(u64 sent_time, u64 recovery_start);

#endif
