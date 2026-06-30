#include "transport/recovery/detect/lossdrive/ptobackoff.h"

#include "common/bytes/util/num.h"
#include "transport/recovery/detect/recovery/pto.h"

u64 quic_lossdrive_pto(
    u64 smoothed_rtt,
    u64 rttvar,
    u64 max_ack_delay,
    u32 pto_count,
    u64 granularity) {
  u64 var  = quic_u64_max(4 * rttvar, granularity);
  u64 base = smoothed_rtt + var + max_ack_delay;
  return base * quic_pto_backoff(pto_count);
}
