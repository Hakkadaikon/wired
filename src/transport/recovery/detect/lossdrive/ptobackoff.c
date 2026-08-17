#include "transport/recovery/detect/lossdrive/ptobackoff.h"

#include "common/bytes/util/num.h"

u64 lossdrive_pto(pto_rtt rtt, const lossdrive_ptoctx* ctx) {
  u64 var  = u64_max(4 * rtt.rttvar, ctx->granularity);
  u64 base = rtt.srtt + var + ctx->max_ack_delay;
  return base * pto_backoff(ctx->pto_count);
}
