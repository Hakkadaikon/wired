#include "transport/recovery/detect/hspto/hspto.h"

#include "common/bytes/util/num.h"
#include "transport/recovery/detect/recovery/pto.h"

/* RFC 9002 6.2.2.1: max_ack_delay is only added once the handshake is
 * confirmed (RFC 9002 6.2.1). */
static u64 ack_delay_term(int handshake_confirmed, u64 max_ack_delay) {
  return handshake_confirmed ? max_ack_delay : 0;
}

u64 quic_hspto_duration(
    u64 srtt,
    u64 rttvar,
    u32 pto_count,
    u64 granularity,
    int handshake_confirmed,
    u64 max_ack_delay) {
  u64 var  = quic_u64_max(4 * rttvar, granularity);
  u64 base = srtt + var + ack_delay_term(handshake_confirmed, max_ack_delay);
  return base * quic_pto_backoff(pto_count);
}
