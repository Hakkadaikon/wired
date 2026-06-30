#include "transport/recovery/detect/recovery/pto.h"

#include "common/bytes/util/num.h"

u64 quic_pto_backoff(u32 count) {
  u32 shift = (count < QUIC_PTO_BACKOFF_MAX) ? count : QUIC_PTO_BACKOFF_MAX;
  return (u64)1 << shift;
}

/* RFC 9002 6.2.1: base PTO before any backoff. */
static u64 base_pto(u64 srtt, u64 rttvar, u64 max_ack_delay) {
  u64 var = quic_u64_max(4 * rttvar, QUIC_PTO_GRANULARITY);
  return srtt + var + max_ack_delay;
}

u64 quic_pto_duration(
    u64 srtt, u64 rttvar, u64 max_ack_delay, u32 backoff_count) {
  return base_pto(srtt, rttvar, max_ack_delay) *
         quic_pto_backoff(backoff_count);
}
