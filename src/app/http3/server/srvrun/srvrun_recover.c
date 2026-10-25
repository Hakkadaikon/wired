#include "app/http3/server/srvrun/srvrun_impl.h"
#include "transport/recovery/detect/lossdrive/lossdelay.h"

/* RFC 9002 6.1.2 / A.10: loss_delay = max(kTimeThreshold *
 * max(smoothed_rtt, latest_rtt), kGranularity), in us. An estimator that
 * was never initialized (rtt_init seeds kInitialRtt, so only a bare
 * zeroed connection has smoothed_rtt 0 without a sample) skips the time
 * threshold instead: 0. */
u64 srvrun_loss_delay_us(const srvrun_conn* c) {
  if (!c->rtt.have_sample && !c->rtt.smoothed_rtt) {
    return 0;
  }
  return lossdrive_loss_delay(
      c->rtt.smoothed_rtt, c->latest_rtt_ms * 1000, RTT_GRANULARITY);
}
