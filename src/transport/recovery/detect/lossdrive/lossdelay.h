#ifndef QUIC_LOSSDRIVE_LOSSDELAY_H
#define QUIC_LOSSDRIVE_LOSSDELAY_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 6.1.2: loss_delay = max(9/8 * max(srtt, latest_rtt), granularity).
 * Times are in microseconds. */
u64 quic_lossdrive_loss_delay(
    u64 smoothed_rtt, u64 latest_rtt, u64 granularity);

#endif
