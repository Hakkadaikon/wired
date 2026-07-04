#include "transport/recovery/detect/lossdrive/ptobackoff.h"

#include "common/bytes/util/num.h"

u64 quic_lossdrive_pto(quic_pto_rtt rtt, const quic_lossdrive_ptoctx* ctx) {
  u64 var  = quic_u64_max(4 * rtt.rttvar, ctx->granularity);
  u64 base = rtt.srtt + var + ctx->max_ack_delay;
  return base * quic_pto_backoff(ctx->pto_count);
}
